package com.shsc.billing;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Iterator;
import java.util.Locale;
import java.util.Optional;

import javax.imageio.ImageIO;
import javax.imageio.ImageReader;
import javax.imageio.stream.ImageInputStream;

import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.shared.persistence.Sql;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;

/**
 * White label of a tenant (ADR-072): name, primary color, support e-mail and a PNG/JPEG logo,
 * shown by the dashboard and in the PDF reports only while the plan allows it ({@code
 * plans.white_label}). Data stays on downgrade but is no longer applied. RLS keeps it per tenant.
 */
@Service
public class BrandingService {

    public record Branding(boolean available, String displayName, String primaryColor, String supportEmail,
            String logoSha256, Instant updatedAt) {
    }

    public record BrandingData(String displayName, String primaryColor, String supportEmail) {
    }

    public record Logo(byte[] bytes, String contentType) {
    }

    static final int MAX_LOGO_BYTES = 256 * 1024;
    static final int MAX_LOGO_SIDE = 2048;

    private final JdbcClient jdbc;
    private final BillingRepository billing;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final Clock clock;

    public BrandingService(JdbcClient jdbc, BillingRepository billing, AccessPolicy access, AuditLog audit,
            Clock clock) {
        this.jdbc = jdbc;
        this.billing = billing;
        this.access = access;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public Branding current() {
        access.require(Permissions.TENANT_READ);
        if (!billing.whiteLabelAllowed()) {
            return new Branding(false, null, null, null, null, null);
        }
        return jdbc.sql("SELECT display_name, primary_color, support_email, logo_sha256, updated_at FROM tenant_branding")
                .query((rs, n) -> new Branding(true, rs.getString("display_name"), rs.getString("primary_color"),
                        rs.getString("support_email"), rs.getString("logo_sha256"), Sql.instant(rs, "updated_at")))
                .optional().orElse(new Branding(true, null, null, null, null, null));
    }

    /** Brand name for the PDF report, only when the plan allows white label (inside a tenant transaction). */
    public Optional<String> reportBrandName() {
        if (!billing.whiteLabelAllowed()) {
            return Optional.empty();
        }
        return jdbc.sql("SELECT display_name FROM tenant_branding").query(String.class).optional();
    }

    @Transactional
    public Branding update(BrandingData data, ClientInfo client) {
        AuthenticatedUser user = requireManage();
        String name = clean(data.displayName(), 80);
        String color = data.primaryColor() == null || data.primaryColor().isBlank() ? null
                : data.primaryColor().strip().toLowerCase(Locale.ROOT);
        if (color != null && !color.matches("#[0-9a-f]{6}")) {
            throw ApiException.badRequest("INVALID_COLOR", "The color must be #RRGGBB.");
        }
        String email = data.supportEmail() == null || data.supportEmail().isBlank() ? null : data.supportEmail().strip();
        jdbc.sql("""
                INSERT INTO tenant_branding (tenant_id, display_name, primary_color, support_email, updated_by, updated_at)
                VALUES (:tenant, :name, :color, :email, :user, :now)
                ON CONFLICT (tenant_id) DO UPDATE SET display_name = EXCLUDED.display_name,
                    primary_color = EXCLUDED.primary_color, support_email = EXCLUDED.support_email,
                    updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at""")
                .param("tenant", user.tenantId()).param("name", name).param("color", color).param("email", email)
                .param("user", user.userId()).param("now", Sql.ts(clock.instant())).update();
        audit(user, client, "SETTINGS");
        return current();
    }

    @Transactional
    public Branding uploadLogo(byte[] bytes, String contentType, ClientInfo client) {
        AuthenticatedUser user = requireManage();
        String type = validateLogo(bytes, contentType);
        jdbc.sql("""
                INSERT INTO tenant_branding (tenant_id, logo, logo_content_type, logo_sha256, updated_by, updated_at)
                VALUES (:tenant, :logo, :type, :sha, :user, :now)
                ON CONFLICT (tenant_id) DO UPDATE SET logo = EXCLUDED.logo, logo_content_type = EXCLUDED.logo_content_type,
                    logo_sha256 = EXCLUDED.logo_sha256, updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at""")
                .param("tenant", user.tenantId()).param("logo", bytes).param("type", type).param("sha", sha256(bytes))
                .param("user", user.userId()).param("now", Sql.ts(clock.instant())).update();
        audit(user, client, "LOGO");
        return current();
    }

    @Transactional
    public Branding deleteLogo(ClientInfo client) {
        AuthenticatedUser user = requireManage();
        jdbc.sql("""
                UPDATE tenant_branding SET logo = NULL, logo_content_type = NULL, logo_sha256 = NULL,
                    updated_by = :user, updated_at = :now""")
                .param("user", user.userId()).param("now", Sql.ts(clock.instant())).update();
        audit(user, client, "LOGO_REMOVED");
        return current();
    }

    @Transactional(readOnly = true)
    public Logo logo() {
        access.require(Permissions.TENANT_READ);
        if (!billing.whiteLabelAllowed()) {
            throw ApiException.notFound();
        }
        return jdbc.sql("SELECT logo, logo_content_type FROM tenant_branding WHERE logo IS NOT NULL")
                .query((rs, n) -> new Logo(rs.getBytes("logo"), rs.getString("logo_content_type")))
                .optional().orElseThrow(ApiException::notFound);
    }

    private AuthenticatedUser requireManage() {
        AuthenticatedUser user = access.requireTenantWide(Permissions.ORGANIZATION_MANAGE);
        if (!billing.whiteLabelAllowed()) {
            throw new ApiException(HttpStatus.CONFLICT, "PLAN_FEATURE_UNAVAILABLE",
                    "White label is not included in your plan.");
        }
        return user;
    }

    private void audit(AuthenticatedUser user, ClientInfo client, String change) {
        audit.record(AuditEvent.of(AuditAction.BRANDING_UPDATED).tenant(user.tenantId()).user(user.userId())
                .client(client).target("TENANT", user.tenantId()).detail("change", change).build());
    }

    /** Trimmed, without control/format characters; null when blank. */
    static String clean(String value, int max) {
        if (value == null || value.isBlank()) {
            return null;
        }
        String v = value.strip();
        if (v.length() > max || v.codePoints().anyMatch(c -> Character.isISOControl(c)
                || Character.getType(c) == Character.FORMAT)) {
            throw ApiException.badRequest("INVALID_NAME", "The name is not valid.");
        }
        return v;
    }

    /**
     * Only PNG or JPEG whose magic bytes match the declared type and whose header can be read with
     * bounded dimensions (the image is not decoded: no decompression bomb). SVG is refused (scripts).
     */
    static String validateLogo(byte[] bytes, String contentType) {
        if (bytes == null || bytes.length == 0 || bytes.length > MAX_LOGO_BYTES) {
            throw ApiException.badRequest("INVALID_LOGO", "The logo must be a PNG or JPEG of at most 256 KB.");
        }
        String type = contentType == null ? "" : contentType.split(";")[0].strip().toLowerCase(Locale.ROOT);
        boolean png = bytes.length > 8 && (bytes[0] & 0xff) == 0x89 && bytes[1] == 'P' && bytes[2] == 'N' && bytes[3] == 'G';
        boolean jpeg = bytes.length > 3 && (bytes[0] & 0xff) == 0xff && (bytes[1] & 0xff) == 0xd8 && (bytes[2] & 0xff) == 0xff;
        if (!(("image/png".equals(type) && png) || ("image/jpeg".equals(type) && jpeg))) {
            throw ApiException.badRequest("INVALID_LOGO", "The logo must be a PNG or JPEG of at most 256 KB.");
        }
        try (ImageInputStream in = ImageIO.createImageInputStream(new ByteArrayInputStream(bytes))) {
            Iterator<ImageReader> readers = ImageIO.getImageReaders(in);
            if (!readers.hasNext()) {
                throw ApiException.badRequest("INVALID_LOGO", "The logo cannot be read.");
            }
            ImageReader reader = readers.next();
            try {
                reader.setInput(in, true, true);
                int w = reader.getWidth(0);
                int h = reader.getHeight(0);
                if (w < 1 || h < 1 || w > MAX_LOGO_SIDE || h > MAX_LOGO_SIDE) {
                    throw ApiException.badRequest("INVALID_LOGO", "The logo must be at most 2048x2048 pixels.");
                }
            } finally {
                reader.dispose();
            }
        } catch (IOException e) {
            throw ApiException.badRequest("INVALID_LOGO", "The logo cannot be read.");
        }
        return type;
    }

    private static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }
}

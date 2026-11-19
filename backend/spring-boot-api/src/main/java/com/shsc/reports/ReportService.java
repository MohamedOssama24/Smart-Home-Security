package com.shsc.reports;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneId;
import java.util.HexFormat;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.billing.BrandingService;
import com.shsc.homes.HomeRepository;
import com.shsc.homes.HomeRepository.Home;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.reports.ReportRenderer.Rendered;
import com.shsc.reports.ReportRepository.Content;
import com.shsc.reports.ReportRepository.Report;
import com.shsc.reports.ReportRepository.ScanScore;
import com.shsc.scans.ScanRepository;
import com.shsc.scans.ScanRepository.Scan;
import com.shsc.scans.ScanRepository.Status;
import com.shsc.shared.persistence.TenantScope;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * PDF security reports of a completed scan (docs/22-ALERTS-REPORTS.md §3): requested with
 * {@code report:generate}, generated in the background after the request commits, stored in the
 * database and downloaded by the users who can read the home's findings.
 */
@Service
public class ReportService implements DisposableBean {

    private static final Logger LOG = LoggerFactory.getLogger(ReportService.class);
    private static final Set<String> LOCALES = Set.of("it", "en");
    /** A report still PENDING after this long was interrupted (e.g. restart): shown as FAILED. */
    static final Duration STALE = Duration.ofMinutes(10);
    private static final int MAX_LIST = 50;

    private final ReportRepository reports;
    private final ReportRenderer renderer;
    private final ScanRepository scans;
    private final HomeRepository homes;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final TenantScope tenantScope;
    private final TransactionTemplate tx;
    private final JsonMapper json;
    private final Clock clock;
    private final int maxPerHomePerDay;
    private final BrandingService branding;
    private final ExecutorService executor = Executors.newVirtualThreadPerTaskExecutor();

    public ReportService(ReportRepository reports, ReportRenderer renderer, ScanRepository scans, HomeRepository homes,
            AccessPolicy access, AuditLog audit, TenantScope tenantScope, TransactionTemplate tx, JsonMapper json,
            Clock clock, BrandingService branding,
            @Value("${shsc.reports.max-per-home-per-day:20}") int maxPerHomePerDay) {
        this.branding = branding;
        this.reports = reports;
        this.renderer = renderer;
        this.scans = scans;
        this.homes = homes;
        this.access = access;
        this.audit = audit;
        this.tenantScope = tenantScope;
        this.tx = tx;
        this.json = json;
        this.clock = clock;
        this.maxPerHomePerDay = maxPerHomePerDay;
    }

    @Transactional
    public Report request(UUID scanId, String locale, ClientInfo client) {
        Scan scan = scans.find(scanId).orElseThrow(ApiException::notFound);
        // the report contains the findings: both permissions are needed
        access.requireOnHome(Permissions.FINDING_READ, scan.homeId());
        AuthenticatedUser user = access.requireOnHome(Permissions.REPORT_GENERATE, scan.homeId());
        String lang = locale == null ? "it" : locale.trim();
        if (!LOCALES.contains(lang)) {
            throw ApiException.badRequest("INVALID_LOCALE", "locale must be it or en.");
        }
        if (scan.status() != Status.COMPLETED && scan.status() != Status.COMPLETED_WITH_WARNINGS) {
            throw ApiException.conflict("SCAN_NOT_COMPLETED", "Reports are generated for completed scans only.");
        }
        Instant now = clock.instant();
        if (reports.pending(scanId, lang)) {
            throw ApiException.conflict("REPORT_IN_PROGRESS", "A report of this scan is already being generated.");
        }
        if (reports.countSince(scan.homeId(), now.minus(Duration.ofDays(1))) >= maxPerHomePerDay) {
            throw new ApiException(HttpStatus.TOO_MANY_REQUESTS, "REPORT_LIMIT",
                    "Too many reports for this home in the last 24 hours.");
        }
        UUID id = reports.insert(scan.tenantId(), scan.homeId(), scanId, lang, user.userId(), now);
        audit.record(AuditEvent.of(AuditAction.REPORT_REQUESTED).tenant(scan.tenantId()).user(user.userId())
                .client(client).target("REPORT", id).detail("homeId", scan.homeId()).detail("scanId", scanId)
                .detail("locale", lang).build());
        UUID tenantId = scan.tenantId();
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                executor.execute(() -> generate(tenantId, id));
            }
        });
        return reports.find(id).orElseThrow();
    }

    /** Background generation: read the data, render outside the transaction, store the PDF. */
    void generate(UUID tenantId, UUID reportId) {
        tenantScope.runAs(tenantId, () -> {
            try {
                ReportData data = tx.execute(status -> load(reportId));
                if (data == null) {
                    return;
                }
                Rendered rendered = renderer.render(data);
                String sha256 = sha256(rendered.pdf());
                tx.executeWithoutResult(status -> reports.ready(reportId, rendered.pdf(), sha256, rendered.pages(),
                        clock.instant()));
                LOG.info("Report {} generated: {} bytes, {} pages", reportId, rendered.pdf().length, rendered.pages());
            } catch (RuntimeException e) {
                LOG.error("Report {} not generated: {}", reportId, e.toString());
                tx.executeWithoutResult(status -> reports.failed(reportId, "GENERATION_FAILED"));
            }
        });
    }

    private ReportData load(UUID reportId) {
        Report r = reports.find(reportId).orElse(null);
        if (r == null || !"PENDING".equals(r.status())) {
            return null;
        }
        Home home = homes.find(r.homeId()).orElseThrow();
        Scan scan = scans.find(r.scanId()).orElseThrow();
        ScanScore score = reports.scanScore(r.scanId()).orElse(null);
        int discovered = 0;
        int analyzed = 0;
        if (score != null && score.coverageDetailJson() != null) {
            JsonNode detail = json.readTree(score.coverageDetailJson());
            discovered = detail.path("hostsDiscovered").asInt();
            analyzed = detail.path("hostsAnalyzed").asInt();
        }
        List<ReportData.Finding> findings = reports.findings(r.homeId()).stream()
                .map(f -> new ReportData.Finding(f.titleKey(), f.recommendationKey(), params(f.paramsJson()),
                        f.severity(), f.type(), f.status(), f.deviceName(), f.deviceIp()))
                .toList();
        List<ReportData.Device> devices = reports.devices(r.homeId()).stream()
                .map(d -> new ReportData.Device(d.name(), d.ip(), d.category(), d.manufacturer())).toList();
        return new ReportData(r.id(), r.locale(), home.name(), zone(home.timezone()), clock.instant(),
                scan.profile(), scan.completedAt(),
                score == null ? null : score.score(), score == null ? null : score.riskLevel(),
                score == null ? null : score.rating(), score == null ? null : score.notComputedReason(),
                score == null ? null : score.coverage().doubleValue(), score != null && score.provisional(),
                discovered, analyzed, findings, devices, branding.reportBrandName().orElse(null));
    }

    @Transactional
    public Report get(UUID id) {
        reports.failStale(clock.instant().minus(STALE));
        Report r = reports.find(id).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.FINDING_READ, r.homeId());
        return r;
    }

    @Transactional
    public List<Report> list(UUID homeId) {
        homes.find(homeId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.FINDING_READ, homeId);
        reports.failStale(clock.instant().minus(STALE));
        return reports.forHome(homeId, MAX_LIST);
    }

    public record Download(Report report, byte[] pdf) {
    }

    @Transactional
    public Download download(UUID id, ClientInfo client) {
        Report r = reports.find(id).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.FINDING_READ, r.homeId());
        Content content = reports.content(id).orElseThrow(() -> ApiException.conflict("REPORT_NOT_READY",
                "The report is not ready."));
        audit.record(AuditEvent.of(AuditAction.REPORT_DOWNLOADED).tenant(r.tenantId()).user(user.userId())
                .client(client).target("REPORT", id).detail("homeId", r.homeId()).build());
        return new Download(r, content.bytes());
    }

    // --- helpers ------------------------------------------------------------------------------

    private Map<String, Object> params(String text) {
        return text == null ? Map.of() : json.readValue(text, new TypeReference<Map<String, Object>>() {
        });
    }

    private static ZoneId zone(String id) {
        try {
            return ZoneId.of(id);
        } catch (RuntimeException e) {
            return ZoneId.of("Europe/Rome");
        }
    }

    static String sha256(byte[] bytes) {
        try {
            return HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException(e);
        }
    }

    @Override
    public void destroy() {
        executor.close();
    }
}

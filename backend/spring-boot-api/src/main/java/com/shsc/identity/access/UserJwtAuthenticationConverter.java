package com.shsc.identity.access;

import java.time.Clock;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.core.convert.converter.Converter;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.stereotype.Component;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.identity.role.RoleAssignmentRepository;
import com.shsc.shared.persistence.Sql;
import com.shsc.shared.persistence.TenantScope;

/**
 * Turns a cryptographically valid access token into an authenticated principal. Binds the
 * tenant of the token to the request (RLS) and re-checks in the database that the session
 * is still active and the user is still enabled, then loads the current role assignments.
 */
@Component
public class UserJwtAuthenticationConverter implements Converter<Jwt, AbstractAuthenticationToken> {

    private record SessionUser(String email, String displayName) {
    }

    private final JdbcClient jdbc;
    private final TransactionTemplate tx;
    private final TenantScope tenantScope;
    private final RoleAssignmentRepository assignments;
    private final RoleCatalog catalog;
    private final Clock clock;

    public UserJwtAuthenticationConverter(JdbcClient jdbc, TransactionTemplate tx, TenantScope tenantScope,
            RoleAssignmentRepository assignments, RoleCatalog catalog, Clock clock) {
        this.jdbc = jdbc;
        this.tx = tx;
        this.tenantScope = tenantScope;
        this.assignments = assignments;
        this.catalog = catalog;
        this.clock = clock;
    }

    @Override
    public AbstractAuthenticationToken convert(Jwt jwt) {
        UUID userId = parse(jwt.getSubject());
        UUID tenantId = parse(jwt.getClaimAsString("tid"));
        UUID sessionId = parse(jwt.getClaimAsString("sid"));

        tenantScope.enter(tenantId);
        AuthenticatedUser principal = tx.execute(status -> {
            Optional<SessionUser> active = jdbc.sql("""
                    SELECT u.email, u.display_name FROM user_sessions s JOIN users u ON u.id = s.user_id
                    WHERE s.id = :session AND s.user_id = :user AND s.revoked_at IS NULL AND s.expires_at > :now
                      AND u.status = 'ACTIVE'""")
                    .param("session", sessionId).param("user", userId).param("now", Sql.ts(clock.instant()))
                    .query((rs, n) -> new SessionUser(rs.getString("email"), rs.getString("display_name")))
                    .optional();
            return active.map(user -> new AuthenticatedUser(userId, tenantId, sessionId, user.email(),
                    user.displayName(), assignments.forUser(userId))).orElse(null);
        });
        if (principal == null) {
            throw new InvalidBearerTokenException("The session is no longer active");
        }
        List<GrantedAuthority> authorities = new ArrayList<>();
        principal.assignments().forEach(a -> {
            authorities.add(new SimpleGrantedAuthority("ROLE_" + a.role()));
            catalog.permissionsOf(a.role()).forEach(p -> authorities.add(new SimpleGrantedAuthority(p)));
        });
        return new UserAuthentication(principal, jwt, authorities.stream().distinct().toList());
    }

    private static UUID parse(String value) {
        try {
            return UUID.fromString(value);
        } catch (RuntimeException e) {
            throw new InvalidBearerTokenException("Malformed token claims");
        }
    }
}

package com.shsc.agents.auth;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Optional;
import java.util.UUID;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import com.nimbusds.jwt.JWTClaimsSet;
import com.shsc.agents.auth.Ed25519.Assertion;
import com.shsc.agents.management.AgentRepository;
import com.shsc.agents.management.AgentRepository.AccessTokenRow;
import com.shsc.agents.management.AgentRepository.Agent;
import com.shsc.agents.management.AgentRepository.AgentStatus;
import com.shsc.agents.management.AgentRepository.Credential;
import com.shsc.agents.management.AgentRepository.EnrollmentToken;
import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.homes.HomeRepository;
import com.shsc.identity.authentication.AuthThrottle;
import com.shsc.shared.config.ShscProperties;
import com.shsc.shared.crypto.SecureTokens;
import com.shsc.shared.persistence.SecurityLookups;
import com.shsc.shared.persistence.SecurityLookups.SecretKind;
import com.shsc.shared.persistence.TenantScope;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;

/**
 * Local agent authentication, separate from user authentication:
 * <ol>
 * <li><b>enroll</b>: one-time, expiring enrollment token + agent-generated Ed25519 public key
 * → agent identity bound to one home;</li>
 * <li><b>token</b>: assertion signed with the agent private key (private_key_jwt style,
 * max 60 s, anti-replay jti) → opaque access token valid 10 minutes, stored hashed;</li>
 * <li><b>rotate</b>: new key proven by a signature made with it; the old key and all tokens
 * are retired immediately;</li>
 * <li>every request re-checks token, credential and agent status: a revocation is effective
 * at the next request.</li>
 * </ol>
 */
@Service
public class AgentAuthService {

    public record EnrollmentRequest(String enrollmentToken, String publicKey, String name, String hostname,
            String os, String arch, String agentVersion) {
    }

    public record Enrolled(UUID agentId, UUID homeId, UUID credentialId) {
    }

    public record IssuedAgentToken(String accessToken, Instant expiresAt, Duration ttl) {
    }

    private static final String ENROLL = "agent-enroll";
    private static final String TOKEN = "agent-token";

    private final AgentRepository agents;
    private final HomeRepository homes;
    private final SecurityLookups lookups;
    private final TenantScope tenantScope;
    private final TransactionTemplate tx;
    private final AuthThrottle throttle;
    private final AuditLog audit;
    private final ShscProperties.Agent settings;
    private final Clock clock;

    public AgentAuthService(AgentRepository agents, HomeRepository homes, SecurityLookups lookups,
            TenantScope tenantScope, TransactionTemplate tx, AuthThrottle throttle, AuditLog audit,
            ShscProperties properties, Clock clock) {
        this.agents = agents;
        this.homes = homes;
        this.lookups = lookups;
        this.tenantScope = tenantScope;
        this.tx = tx;
        this.throttle = throttle;
        this.audit = audit;
        this.settings = properties.agent();
        this.clock = clock;
    }

    // ------------------------------------------------------------------ enrollment

    public Enrolled enroll(EnrollmentRequest request, ClientInfo client) {
        String ipKey = AuthThrottle.ipKey(ENROLL, client.ip());
        throttle.ensureNotBlocked(ipKey);
        byte[] publicKey;
        try {
            publicKey = Ed25519.decodePublicKey(request.publicKey());
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("INVALID_PUBLIC_KEY", "The public key must be a base64url Ed25519 key.");
        }
        byte[] hash = SecureTokens.sha256(request.enrollmentToken());
        Optional<UUID> tenantId = lookups.tenantBySecret(SecretKind.AGENT_ENROLLMENT_TOKEN, hash);
        if (tenantId.isEmpty()) {
            throw enrollmentRejected(ipKey, null, "UNKNOWN_TOKEN", client);
        }
        Enrolled enrolled;
        try {
            enrolled = tenantScope.callAs(tenantId.get(), () -> tx.execute(status -> {
                Instant now = clock.instant();
                EnrollmentToken token = agents.lockEnrollmentTokenByHash(hash).orElse(null);
                if (token == null || !"ACTIVE".equals(token.state(now)) || homes.find(token.homeId()).isEmpty()) {
                    return null;
                }
                String name = firstNonBlank(request.name(), request.hostname(), "agent");
                UUID agentId = agents.insertAgent(tenantId.get(), token.homeId(), name, request.hostname(),
                        request.os(), request.arch(), request.agentVersion(), now);
                UUID credentialId = agents.insertCredential(tenantId.get(), agentId, publicKey, now);
                agents.markEnrollmentTokenUsed(token.id(), agentId, now);
                audit.record(AuditEvent.of(AuditAction.AGENT_ENROLLED).tenant(tenantId.get()).agent(agentId)
                        .target("AGENT", agentId).client(client).detail("homeId", token.homeId())
                        .detail("enrollmentTokenId", token.id()).detail("os", request.os())
                        .detail("agentVersion", request.agentVersion()).build());
                return new Enrolled(agentId, token.homeId(), credentialId);
            }));
        } catch (DuplicateKeyException e) {
            throw ApiException.conflict("PUBLIC_KEY_IN_USE", "This public key is already registered.");
        }
        if (enrolled == null) {
            throw enrollmentRejected(ipKey, tenantId.get(), "TOKEN_NOT_USABLE", client);
        }
        return enrolled;
    }

    private ApiException enrollmentRejected(String ipKey, UUID tenantId, String reason, ClientInfo client) {
        throttle.ipFailure(ipKey);
        audit.record(AuditEvent.of(AuditAction.AGENT_ENROLLMENT_FAILED).tenant(tenantId).failure(reason)
                .client(client).build());
        return ApiException.unauthorized("INVALID_ENROLLMENT_TOKEN",
                "The enrollment token is not valid, expired, revoked or already used.");
    }

    // ------------------------------------------------------------------ access token

    public IssuedAgentToken issueToken(String assertionValue, ClientInfo client) {
        String ipKey = AuthThrottle.ipKey(TOKEN, client.ip());
        throttle.ensureNotBlocked(ipKey);
        Assertion assertion;
        UUID agentId;
        try {
            assertion = Assertion.parse(assertionValue);
            agentId = UUID.fromString(assertion.claims().getIssuer());
        } catch (IllegalArgumentException | NullPointerException e) {
            throw agentAuthFailed(ipKey, null, null, "MALFORMED_ASSERTION", client);
        }
        String claimsProblem = validateClaims(assertion.claims(), agentId, settings.assertionAudience());
        if (claimsProblem != null) {
            throw agentAuthFailed(ipKey, null, agentId, claimsProblem, client);
        }
        UUID tenantId = lookups.tenantOfAgent(agentId).orElse(null);
        if (tenantId == null) {
            throw agentAuthFailed(ipKey, null, agentId, "UNKNOWN_AGENT", client);
        }
        Object result = tenantScope.callAs(tenantId, () -> tx.execute(status -> {
            Instant now = clock.instant();
            Agent agent = agents.lock(agentId).orElse(null);
            if (agent == null) {
                return "UNKNOWN_AGENT";
            }
            if (agent.status() == AgentStatus.REVOKED) {
                return "AGENT_REVOKED";
            }
            Credential credential = agents.activeCredential(agentId).orElse(null);
            if (credential == null || !assertion.verify(credential.publicKey())) {
                return "BAD_SIGNATURE";
            }
            Instant assertionExpiry = assertion.claims().getExpirationTime().toInstant();
            if (!agents.rememberAssertion(tenantId, agentId, assertion.claims().getJWTID(), assertionExpiry)) {
                return "ASSERTION_REPLAYED";
            }
            String token = SecureTokens.generate(SecureTokens.AGENT_ACCESS_TOKEN_PREFIX);
            Instant expiresAt = now.plus(settings.accessTokenTtl());
            agents.insertAccessToken(tenantId, agentId, credential.id(), SecureTokens.sha256(token), now, expiresAt);
            agents.touch(agentId, now);
            return new IssuedAgentToken(token, expiresAt, settings.accessTokenTtl());
        }));
        if (result instanceof IssuedAgentToken issued) {
            return issued;
        }
        String reason = (String) result;
        ApiException failure = agentAuthFailed(ipKey, tenantId, agentId, reason, client);
        if ("AGENT_REVOKED".equals(reason)) {
            throw ApiException.unauthorized("AGENT_REVOKED", "The agent has been revoked. Enroll it again.");
        }
        throw failure;
    }

    // ------------------------------------------------------------------ authentication of requests

    /** Resolves a bearer token to an agent principal, or empty if not valid anymore. */
    public Optional<AgentPrincipal> authenticate(String bearer) {
        if (bearer == null || !bearer.startsWith(SecureTokens.AGENT_ACCESS_TOKEN_PREFIX) || bearer.length() > 200) {
            return Optional.empty();
        }
        byte[] hash = SecureTokens.sha256(bearer);
        Optional<UUID> tenantId = lookups.tenantBySecret(SecretKind.AGENT_ACCESS_TOKEN, hash);
        if (tenantId.isEmpty()) {
            return Optional.empty();
        }
        tenantScope.enter(tenantId.get());
        return tx.execute(status -> {
            Optional<AccessTokenRow> row = agents.findValidAccessToken(hash, clock.instant());
            return row.flatMap(token -> agents.find(token.agentId()).map(agent -> new AgentPrincipal(agent.id(),
                    tenantId.get(), agent.homeId(), token.credentialId(), token.expiresAt())));
        });
    }

    /** True if the token belongs to an agent that has been revoked (to answer AGENT_REVOKED). */
    public boolean isRevokedAgentToken(String bearer) {
        if (bearer == null || !bearer.startsWith(SecureTokens.AGENT_ACCESS_TOKEN_PREFIX)) {
            return false;
        }
        byte[] hash = SecureTokens.sha256(bearer);
        return lookups.tenantBySecret(SecretKind.AGENT_ACCESS_TOKEN, hash)
                .map(tenant -> tenantScope.callAs(tenant, () -> tx.execute(status -> agents.agentOfAccessToken(hash)
                        .flatMap(agents::find).map(a -> a.status() == AgentStatus.REVOKED).orElse(false))))
                .orElse(false);
    }

    // ------------------------------------------------------------------ key rotation

    /** Replaces the agent key. {@code proof} is an assertion signed with the NEW key. */
    public UUID rotate(AgentPrincipal principal, String newPublicKey, String proof, ClientInfo client) {
        byte[] publicKey;
        Assertion assertion;
        try {
            publicKey = Ed25519.decodePublicKey(newPublicKey);
            assertion = Assertion.parse(proof);
        } catch (IllegalArgumentException e) {
            throw ApiException.badRequest("INVALID_ROTATION", "Invalid public key or proof.");
        }
        String claimsProblem = validateClaims(assertion.claims(), principal.agentId(), settings.rotationAudience());
        if (claimsProblem != null || !assertion.verify(publicKey)) {
            audit.record(AuditEvent.of(AuditAction.AGENT_AUTHENTICATION_FAILED).tenant(principal.tenantId())
                    .agent(principal.agentId()).failure(claimsProblem == null ? "BAD_ROTATION_PROOF" : claimsProblem)
                    .client(client).build());
            throw ApiException.badRequest("INVALID_ROTATION", "The proof of possession of the new key is not valid.");
        }
        try {
            return tx.execute(status -> {
                Instant now = clock.instant();
                agents.lock(principal.agentId()).filter(a -> a.status() == AgentStatus.ACTIVE)
                        .orElseThrow(() -> ApiException.unauthorized("AGENT_REVOKED", "The agent has been revoked."));
                Credential current = agents.activeCredential(principal.agentId())
                        .filter(c -> c.id().equals(principal.credentialId()))
                        .orElseThrow(() -> ApiException.conflict("CREDENTIAL_CHANGED", "The credential was already rotated."));
                if (!agents.rememberAssertion(principal.tenantId(), principal.agentId(), assertion.claims().getJWTID(),
                        assertion.claims().getExpirationTime().toInstant())) {
                    throw ApiException.badRequest("INVALID_ROTATION", "The proof was already used.");
                }
                agents.retireCredential(current.id(), now);
                UUID credentialId = agents.insertCredential(principal.tenantId(), principal.agentId(), publicKey, now);
                agents.revokeAccessTokens(principal.agentId(), now);
                audit.record(AuditEvent.of(AuditAction.AGENT_CREDENTIAL_ROTATED).tenant(principal.tenantId())
                        .agent(principal.agentId()).target("AGENT", principal.agentId()).client(client)
                        .detail("previousCredentialId", current.id()).detail("credentialId", credentialId).build());
                return credentialId;
            });
        } catch (DuplicateKeyException e) {
            throw ApiException.conflict("PUBLIC_KEY_IN_USE", "This public key is already registered.");
        }
    }

    /** Agent ↔ home association check used by every agent endpoint. */
    public HomeRepository.Home requireHome(AgentPrincipal principal) {
        return tx.execute(status -> {
            Agent agent = agents.find(principal.agentId())
                    .filter(a -> a.status() == AgentStatus.ACTIVE)
                    .orElseThrow(() -> ApiException.unauthorized("AGENT_REVOKED", "The agent has been revoked."));
            if (!agent.homeId().equals(principal.homeId())) {
                throw new ApiException(HttpStatus.FORBIDDEN, "AGENT_HOME_MISMATCH", "The agent is not bound to this home.");
            }
            return homes.find(agent.homeId()).orElseThrow(() -> new ApiException(HttpStatus.FORBIDDEN,
                    "AGENT_HOME_MISMATCH", "The home of this agent is no longer available."));
        });
    }

    // ------------------------------------------------------------------ helpers

    /** Returns null when valid, otherwise a short reason code. */
    private String validateClaims(JWTClaimsSet claims, UUID agentId, String audience) {
        Instant now = clock.instant();
        Duration skew = settings.clockSkew();
        Date iat = claims.getIssueTime();
        Date exp = claims.getExpirationTime();
        String jti = claims.getJWTID();
        if (!agentId.toString().equals(claims.getIssuer()) || !agentId.toString().equals(claims.getSubject())) {
            return "BAD_ISSUER";
        }
        if (claims.getAudience() == null || !claims.getAudience().contains(audience)) {
            return "BAD_AUDIENCE";
        }
        if (iat == null || exp == null || jti == null || jti.length() < 16 || jti.length() > 128) {
            return "MISSING_CLAIMS";
        }
        if (exp.toInstant().isBefore(now.minus(skew)) || iat.toInstant().isAfter(now.plus(skew))) {
            return "EXPIRED_ASSERTION";
        }
        if (Duration.between(iat.toInstant(), exp.toInstant()).compareTo(settings.assertionMaxLifetime()) > 0) {
            return "ASSERTION_TOO_LONG";
        }
        return null;
    }

    private ApiException agentAuthFailed(String ipKey, UUID tenantId, UUID agentId, String reason, ClientInfo client) {
        throttle.ipFailure(ipKey);
        AuditEvent.Builder event = AuditEvent.of(AuditAction.AGENT_AUTHENTICATION_FAILED).tenant(tenantId)
                .failure(reason).client(client);
        if (tenantId != null && agentId != null) {
            event.target("AGENT", agentId);
        }
        audit.record(event.build());
        return ApiException.unauthorized("INVALID_AGENT_ASSERTION", "The agent could not be authenticated.");
    }

    private static String firstNonBlank(String... values) {
        for (String value : values) {
            if (value != null && !value.isBlank()) {
                return value.trim();
            }
        }
        return null;
    }
}

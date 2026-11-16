package com.shsc.agents.auth;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

/** Identity of an authenticated agent request. Never confused with a user principal. */
public record AgentPrincipal(UUID agentId, UUID tenantId, UUID homeId, UUID credentialId, Instant tokenExpiresAt) {

    public static final String ROLE = "ROLE_AGENT";

    /** Spring Security authentication carrying the agent principal. */
    public static final class AgentAuthentication extends AbstractAuthenticationToken {

        private final AgentPrincipal principal;

        public AgentAuthentication(AgentPrincipal principal) {
            super(List.of(new SimpleGrantedAuthority(ROLE)));
            this.principal = principal;
            setAuthenticated(true);
        }

        @Override
        public Object getCredentials() {
            return null;
        }

        @Override
        public AgentPrincipal getPrincipal() {
            return principal;
        }

        @Override
        public String getName() {
            return principal.agentId().toString();
        }
    }
}

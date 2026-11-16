package com.shsc.agents.auth;

import java.io.IOException;
import java.util.Optional;

import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import com.shsc.agents.auth.AgentPrincipal.AgentAuthentication;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

/**
 * Authenticates {@code /api/v1/agent/**} requests with an agent access token. User JWTs are
 * never accepted here (different format, not in the agent token table) and agent tokens are
 * never accepted by the user API (not a valid ES256 JWT). Unauthenticated requests continue
 * as anonymous and are rejected by the authorization rules with 401.
 */
public class AgentAuthenticationFilter extends OncePerRequestFilter {

    static final String REVOKED_ATTRIBUTE = AgentAuthenticationFilter.class.getName() + ".revoked";

    private final AgentAuthService agentAuth;

    public AgentAuthenticationFilter(AgentAuthService agentAuth) {
        this.agentAuth = agentAuth;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        String header = request.getHeader(HttpHeaders.AUTHORIZATION);
        if (header != null && header.regionMatches(true, 0, "Bearer ", 0, 7)) {
            String token = header.substring(7).trim();
            Optional<AgentPrincipal> principal = agentAuth.authenticate(token);
            if (principal.isPresent()) {
                SecurityContext context = SecurityContextHolder.createEmptyContext();
                context.setAuthentication(new AgentAuthentication(principal.get()));
                SecurityContextHolder.setContext(context);
            } else if (agentAuth.isRevokedAgentToken(token)) {
                request.setAttribute(REVOKED_ATTRIBUTE, Boolean.TRUE);
            }
        }
        chain.doFilter(request, response);
    }

    public static boolean isRevoked(HttpServletRequest request) {
        return Boolean.TRUE.equals(request.getAttribute(REVOKED_ATTRIBUTE));
    }
}

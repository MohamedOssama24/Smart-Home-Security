package com.shsc.security;

import java.io.IOException;
import java.util.Map;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.csrf.CsrfException;
import org.springframework.stereotype.Component;

import com.shsc.agents.auth.AgentAuthenticationFilter;
import com.shsc.shared.web.ApiException;

import jakarta.servlet.http.HttpServletResponse;
import tools.jackson.databind.json.JsonMapper;

/** 401/403 produced by Spring Security, rendered as RFC 9457 Problem Details. */
@Component
public class ProblemResponses {

    private final JsonMapper json;

    public ProblemResponses(JsonMapper json) {
        this.json = json;
    }

    public AuthenticationEntryPoint userEntryPoint() {
        return (request, response, exception) -> {
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
            write(response, HttpStatus.UNAUTHORIZED, "UNAUTHENTICATED",
                    "A valid access token is required.");
        };
    }

    public AuthenticationEntryPoint agentEntryPoint() {
        return (request, response, exception) -> {
            response.setHeader(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
            if (AgentAuthenticationFilter.isRevoked(request)) {
                write(response, HttpStatus.UNAUTHORIZED, "AGENT_REVOKED", "The agent has been revoked. Enroll it again.");
            } else {
                write(response, HttpStatus.UNAUTHORIZED, "INVALID_AGENT_TOKEN", "A valid agent access token is required.");
            }
        };
    }

    public AccessDeniedHandler accessDeniedHandler() {
        return (request, response, exception) -> {
            if (exception instanceof CsrfException) {
                write(response, HttpStatus.FORBIDDEN, "CSRF_INVALID",
                        "Missing or invalid CSRF token. Reload the page and try again.");
            } else {
                write(response, HttpStatus.FORBIDDEN, "FORBIDDEN", "You are not allowed to perform this operation.");
            }
        };
    }

    private void write(HttpServletResponse response, HttpStatus status, String code, String detail) throws IOException {
        ProblemDetail problem = ApiException.problem(status, code, detail, Map.of());
        response.setStatus(status.value());
        response.setContentType(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        response.getWriter().write(json.writeValueAsString(problem));
    }
}

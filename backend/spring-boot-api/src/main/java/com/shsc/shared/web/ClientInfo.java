package com.shsc.shared.web;

import org.springframework.http.HttpHeaders;

import jakarta.servlet.http.HttpServletRequest;

/**
 * Client address and user agent of a request. The address comes from
 * {@code request.getRemoteAddr()}, already resolved from X-Forwarded-For by Spring's
 * forwarded-header support; Nginx (the only proxy) overwrites that header.
 */
public record ClientInfo(String ip, String userAgent) {

    private static final int MAX_USER_AGENT = 512;

    public static ClientInfo from(HttpServletRequest request) {
        String agent = request.getHeader(HttpHeaders.USER_AGENT);
        if (agent != null && agent.length() > MAX_USER_AGENT) {
            agent = agent.substring(0, MAX_USER_AGENT);
        }
        String ip = request.getRemoteAddr();
        if (ip != null && ip.length() > 64) {
            ip = ip.substring(0, 64);
        }
        return new ClientInfo(ip, agent);
    }
}

package com.shsc.identity.access;

import java.util.List;
import java.util.UUID;

/**
 * Principal of an authenticated user request. Built for every request from the database
 * (session still active, user active, current role assignments), so revocations and
 * permission changes take effect immediately, not when the access token expires.
 */
public record AuthenticatedUser(
        UUID userId,
        UUID tenantId,
        UUID sessionId,
        String email,
        String displayName,
        List<RoleAssignment> assignments) {
}

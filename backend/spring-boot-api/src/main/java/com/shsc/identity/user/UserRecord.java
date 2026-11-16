package com.shsc.identity.user;

import java.time.Instant;
import java.util.UUID;

public record UserRecord(
        UUID id,
        UUID tenantId,
        String email,
        String passwordHash,
        String displayName,
        String locale,
        Status status,
        Instant emailVerifiedAt,
        Instant lastLoginAt,
        Instant createdAt) {

    public enum Status { PENDING_VERIFICATION, ACTIVE, DISABLED }
}

package com.shsc.audit;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;

import com.shsc.shared.web.ClientInfo;

/**
 * One security-relevant event. {@code details} must never contain secrets, tokens or
 * passwords; e-mails of unknown accounts are stored only as SHA-256.
 */
public record AuditEvent(
        UUID tenantId,
        ActorType actorType,
        UUID actorId,
        AuditAction action,
        Outcome outcome,
        String targetType,
        UUID targetId,
        ClientInfo client,
        Map<String, Object> details) {

    public enum ActorType { USER, AGENT, SYSTEM, ANONYMOUS }

    public enum Outcome { SUCCESS, FAILURE }

    public static Builder of(AuditAction action) {
        return new Builder(action);
    }

    public static final class Builder {
        private final AuditAction action;
        private UUID tenantId;
        private ActorType actorType = ActorType.ANONYMOUS;
        private UUID actorId;
        private Outcome outcome = Outcome.SUCCESS;
        private String targetType;
        private UUID targetId;
        private ClientInfo client;
        private final Map<String, Object> details = new LinkedHashMap<>();

        private Builder(AuditAction action) {
            this.action = action;
        }

        public Builder tenant(UUID tenantId) {
            this.tenantId = tenantId;
            return this;
        }

        public Builder user(UUID userId) {
            this.actorType = ActorType.USER;
            this.actorId = userId;
            return this;
        }

        public Builder agent(UUID agentId) {
            this.actorType = ActorType.AGENT;
            this.actorId = agentId;
            return this;
        }

        public Builder system() {
            this.actorType = ActorType.SYSTEM;
            this.actorId = null;
            return this;
        }

        public Builder failure(String reason) {
            this.outcome = Outcome.FAILURE;
            this.details.put("reason", reason);
            return this;
        }

        public Builder target(String type, UUID id) {
            this.targetType = type;
            this.targetId = id;
            return this;
        }

        public Builder client(ClientInfo client) {
            this.client = client;
            return this;
        }

        public Builder detail(String key, Object value) {
            if (value != null) {
                this.details.put(key, value);
            }
            return this;
        }

        public AuditEvent build() {
            return new AuditEvent(tenantId, actorType, actorId, action, outcome, targetType, targetId, client,
                    Map.copyOf(details));
        }
    }
}

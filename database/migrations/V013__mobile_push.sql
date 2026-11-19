-- Milestone 14 — Flutter app: push notifications (docs/23-MOBILE-APP.md)
--
-- * push_devices: FCM registration tokens of the mobile app, one per installation, bound to the
--   login session that registered them. A revoked or expired session (logout, revocation,
--   password change) stops the pushes of its devices without any extra step.
-- * the PUSH channel joins DASHBOARD and EMAIL in deliveries and preferences.

CREATE TABLE push_devices (
    id            uuid PRIMARY KEY DEFAULT uuidv7(),
    tenant_id     uuid NOT NULL REFERENCES tenants (id),
    user_id       uuid NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    session_id    uuid NOT NULL REFERENCES user_sessions (id) ON DELETE CASCADE,
    platform      text NOT NULL CHECK (platform IN ('ANDROID', 'IOS')),
    -- FCM registration token: opaque, not a credential of the user, treated as personal data
    token         text NOT NULL CHECK (token ~ '^[A-Za-z0-9:_-]+$' AND length(token) BETWEEN 20 AND 4096),
    locale        text NOT NULL CHECK (locale IN ('it', 'en')),
    created_at    timestamptz NOT NULL,
    last_seen_at  timestamptz NOT NULL,
    -- the same installation registering again (new login) moves the token to the new session
    UNIQUE (tenant_id, token)
);
CREATE INDEX push_devices_user_idx ON push_devices (tenant_id, user_id);

ALTER TABLE push_devices ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON push_devices
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

ALTER TABLE alert_deliveries DROP CONSTRAINT alert_deliveries_channel_check;
ALTER TABLE alert_deliveries ADD CONSTRAINT alert_deliveries_channel_check
    CHECK (channel IN ('DASHBOARD', 'EMAIL', 'PUSH'));
ALTER TABLE notification_preferences DROP CONSTRAINT notification_preferences_channel_check;
ALTER TABLE notification_preferences ADD CONSTRAINT notification_preferences_channel_check
    CHECK (channel IN ('DASHBOARD', 'EMAIL', 'PUSH'));

-- pending deliveries of one channel (EMAIL or PUSH), across tenants, ids only
DROP FUNCTION alert_emails_due(timestamptz, integer);
CREATE FUNCTION alert_deliveries_due(p_channel text, p_now timestamptz, p_limit integer)
    RETURNS TABLE (tenant_id uuid, delivery_id uuid)
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = shsc, pg_temp
AS $$
    SELECT d.tenant_id, d.id FROM shsc.alert_deliveries d
    WHERE d.channel = p_channel AND d.status = 'PENDING' AND d.next_attempt_at <= p_now
    ORDER BY d.next_attempt_at
    LIMIT p_limit
$$;
REVOKE EXECUTE ON FUNCTION alert_deliveries_due(text, timestamptz, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION alert_deliveries_due(text, timestamptz, integer) TO ${appRole};

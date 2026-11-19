-- Milestone 18 (hardening): row level security on stripe_webhook_events.
-- V015 left it without RLS ("only Stripe ids"), but it carries tenant_id and the platform rule
-- (DatabaseBaselineTest) is that every tenant-scoped table is isolated by RLS. The webhook reads and
-- writes it only inside the tenant scope of the event's customer (BillingService.webhook), and a
-- Stripe event always belongs to that customer, so the idempotency check is unaffected.

ALTER TABLE stripe_webhook_events ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON stripe_webhook_events
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

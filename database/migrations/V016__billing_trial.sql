-- Milestone 17 — Free trial (ADR-072). One trial per tenant: offered only until the tenant has had a
-- Stripe subscription. Trial state comes from webhooks like the rest of the subscription.
ALTER TABLE tenant_subscriptions
    ADD COLUMN trial_end  timestamptz,
    -- set by the first subscription event: no further trial for the tenant
    ADD COLUMN trial_used boolean NOT NULL DEFAULT false,
    -- the current subscription has been paid at least once (status active): only then past_due keeps
    -- the paid plan during Stripe retries; a failed first payment after the trial applies FREE at once
    ADD COLUMN has_paid   boolean NOT NULL DEFAULT false;

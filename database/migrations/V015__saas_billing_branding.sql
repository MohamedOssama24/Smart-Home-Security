-- Milestone 17: SaaS plans, Stripe subscriptions and white label (docs/26-SAAS-BILLING.md, ADR-072).
--
-- * plans: paid plans PLUS (households) and PRO (businesses, white label). tenant_types limits who
--   can subscribe a plan. Prices live only in Stripe (the Price id of each plan is configuration).
-- * tenant_subscriptions: one Stripe customer/subscription per tenant (RLS). Written only by the
--   checkout (customer id) and by the verified webhooks (subscription state). tenants.plan_code is
--   the effective plan derived from it.
-- * billing_lookup_tenant: SECURITY DEFINER lookup of the tenant of a Stripe customer, used by the
--   webhook (no user, no tenant yet) to open a tenant-scoped transaction.
-- * stripe_webhook_events: ids of the processed events (idempotency). No payload, no RLS: it only
--   holds Stripe ids, the event type and the outcome; the runtime role cannot update or delete it.
-- * tenant_branding: white label of a tenant (name, color, support e-mail, PNG/JPEG logo), applied
--   only while the plan allows it. Nothing is deleted on downgrade.

ALTER TABLE plans
    ADD COLUMN tenant_types text[] NOT NULL DEFAULT ARRAY['INDIVIDUAL', 'BUSINESS']
        CHECK (tenant_types <@ ARRAY['INDIVIDUAL', 'BUSINESS'] AND cardinality(tenant_types) > 0),
    ADD COLUMN white_label boolean NOT NULL DEFAULT false,
    ADD COLUMN sort_order  integer NOT NULL DEFAULT 0;

INSERT INTO plans (code, description, max_homes, max_users, max_customers, max_networks_per_home,
                   max_agents_per_home, max_scans_per_day, tenant_types, white_label, sort_order) VALUES
    ('PLUS', 'Plus plan (households)',                   5,  6,  0, 6, 3, 30, ARRAY['INDIVIDUAL'], false, 1),
    ('PRO',  'Pro plan (installers, small businesses)', 50, 20, 50, 8, 5, 50, ARRAY['BUSINESS'],   true,  2);

-- ---------------------------------------------------------------------------
-- Stripe subscription of a tenant
-- ---------------------------------------------------------------------------
CREATE TABLE tenant_subscriptions (
    tenant_id               uuid PRIMARY KEY REFERENCES tenants (id),
    stripe_customer_id      text NOT NULL UNIQUE CHECK (stripe_customer_id ~ '^cus_[A-Za-z0-9]{1,250}$'),
    stripe_subscription_id  text UNIQUE CHECK (stripe_subscription_id ~ '^sub_[A-Za-z0-9]{1,250}$'),
    plan_code               text REFERENCES plans (code),
    status                  text CHECK (status IN ('incomplete', 'incomplete_expired', 'trialing', 'active',
                                                   'past_due', 'canceled', 'unpaid', 'paused')),
    current_period_end      timestamptz,
    cancel_at_period_end    boolean NOT NULL DEFAULT false,
    -- created time of the last applied subscription event: older events are ignored (out of order)
    last_event_at           timestamptz,
    created_at              timestamptz NOT NULL DEFAULT now(),
    updated_at              timestamptz NOT NULL DEFAULT now()
);

ALTER TABLE tenant_subscriptions ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_subscriptions
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

CREATE FUNCTION billing_lookup_tenant(p_customer text)
    RETURNS uuid
    LANGUAGE sql STABLE SECURITY DEFINER SET search_path = shsc, pg_temp
AS $$
    SELECT tenant_id FROM shsc.tenant_subscriptions WHERE stripe_customer_id = p_customer
$$;
REVOKE EXECUTE ON FUNCTION billing_lookup_tenant(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION billing_lookup_tenant(text) TO ${appRole};

CREATE TABLE stripe_webhook_events (
    event_id     text PRIMARY KEY CHECK (event_id ~ '^evt_[A-Za-z0-9]{1,250}$'),
    type         text NOT NULL CHECK (type ~ '^[a-z0-9_.]{1,100}$'),
    tenant_id    uuid REFERENCES tenants (id),
    outcome      text NOT NULL CHECK (outcome IN ('APPLIED', 'IGNORED', 'STALE')),
    received_at  timestamptz NOT NULL DEFAULT now()
);
REVOKE UPDATE, DELETE, TRUNCATE ON stripe_webhook_events FROM ${appRole};

-- ---------------------------------------------------------------------------
-- White label
-- ---------------------------------------------------------------------------
CREATE TABLE tenant_branding (
    tenant_id          uuid PRIMARY KEY REFERENCES tenants (id),
    display_name       text CHECK (length(display_name) BETWEEN 1 AND 80),
    primary_color      text CHECK (primary_color ~ '^#[0-9a-f]{6}$'),
    support_email      citext CHECK (length(support_email) BETWEEN 3 AND 254),
    logo               bytea CHECK (octet_length(logo) BETWEEN 1 AND 262144),
    logo_content_type  text CHECK (logo_content_type IN ('image/png', 'image/jpeg')),
    logo_sha256        text CHECK (logo_sha256 ~ '^[0-9a-f]{64}$'),
    updated_by         uuid REFERENCES users (id),
    updated_at         timestamptz NOT NULL DEFAULT now(),
    CHECK ((logo IS NULL) = (logo_content_type IS NULL) AND (logo IS NULL) = (logo_sha256 IS NULL))
);

ALTER TABLE tenant_branding ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_branding
    USING (tenant_id = current_tenant_id()) WITH CHECK (tenant_id = current_tenant_id());

-- ---------------------------------------------------------------------------
-- Permissions
-- ---------------------------------------------------------------------------
INSERT INTO permissions (code, description) VALUES
    ('billing:manage', 'Manage the subscription of the tenant (Stripe checkout and portal)');

INSERT INTO role_permissions (role_code, permission_code) VALUES
    ('SUPER_ADMIN', 'billing:manage'), ('ORGANIZATION_ADMIN', 'billing:manage'), ('CUSTOMER', 'billing:manage');

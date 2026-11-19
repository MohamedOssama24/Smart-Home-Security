package com.shsc.billing;

import java.time.Instant;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

import com.shsc.shared.persistence.Sql;

/** Plans, the Stripe subscription of the tenant (RLS) and the processed webhook events. */
@Repository
public class BillingRepository {

    public record PlanInfo(String code, String description, List<String> tenantTypes, boolean whiteLabel,
            Integer maxHomes, Integer maxUsers, Integer maxCustomers, Integer maxNetworksPerHome,
            Integer maxAgentsPerHome, Integer maxScansPerDay) {
    }

    public record Subscription(UUID tenantId, String customerId, String subscriptionId, String planCode,
            String status, Instant currentPeriodEnd, boolean cancelAtPeriodEnd, Instant lastEventAt, Instant trialEnd,
            boolean trialUsed, boolean hasPaid) {
    }

    private final JdbcClient jdbc;

    public BillingRepository(JdbcClient jdbc) {
        this.jdbc = jdbc;
    }

    public List<PlanInfo> plans() {
        return jdbc.sql("""
                SELECT code, description, tenant_types, white_label, max_homes, max_users, max_customers,
                    max_networks_per_home, max_agents_per_home, max_scans_per_day
                FROM plans ORDER BY sort_order, code""")
                .query((rs, n) -> new PlanInfo(rs.getString("code"), rs.getString("description"),
                        Arrays.asList((String[]) rs.getArray("tenant_types").getArray()), rs.getBoolean("white_label"),
                        rs.getObject("max_homes", Integer.class), rs.getObject("max_users", Integer.class),
                        rs.getObject("max_customers", Integer.class), rs.getObject("max_networks_per_home", Integer.class),
                        rs.getObject("max_agents_per_home", Integer.class), rs.getObject("max_scans_per_day", Integer.class)))
                .list();
    }

    public Optional<PlanInfo> plan(String code) {
        return plans().stream().filter(p -> p.code().equals(code)).findFirst();
    }

    /** White label allowed by the effective plan of the current tenant. */
    public boolean whiteLabelAllowed() {
        return jdbc.sql("SELECT p.white_label FROM tenants t JOIN plans p ON p.code = t.plan_code")
                .query(Boolean.class).optional().orElse(false);
    }

    public Optional<Subscription> subscription(boolean lock) {
        return jdbc.sql("""
                SELECT tenant_id, stripe_customer_id, stripe_subscription_id, plan_code, status, current_period_end,
                    cancel_at_period_end, last_event_at, trial_end, trial_used, has_paid
                FROM tenant_subscriptions""" + (lock ? " FOR UPDATE" : ""))
                .query((rs, n) -> new Subscription(Sql.uuid(rs, "tenant_id"), rs.getString("stripe_customer_id"),
                        rs.getString("stripe_subscription_id"), rs.getString("plan_code"), rs.getString("status"),
                        Sql.instant(rs, "current_period_end"), rs.getBoolean("cancel_at_period_end"),
                        Sql.instant(rs, "last_event_at"), Sql.instant(rs, "trial_end"), rs.getBoolean("trial_used"),
                        rs.getBoolean("has_paid")))
                .optional();
    }

    /** Stores the Stripe customer of the tenant unless one is already stored. */
    public void insertCustomer(UUID tenantId, String customerId, Instant now) {
        jdbc.sql("""
                INSERT INTO tenant_subscriptions (tenant_id, stripe_customer_id, created_at, updated_at)
                VALUES (:tenant, :customer, :now, :now) ON CONFLICT (tenant_id) DO NOTHING""")
                .param("tenant", tenantId).param("customer", customerId).param("now", Sql.ts(now)).update();
    }

    public void linkSubscription(String subscriptionId, Instant now) {
        jdbc.sql("""
                UPDATE tenant_subscriptions SET stripe_subscription_id = :sub, trial_used = true, updated_at = :now
                WHERE stripe_subscription_id IS NULL OR stripe_subscription_id = :sub""")
                .param("sub", subscriptionId).param("now", Sql.ts(now)).update();
    }

    public void updateSubscription(String subscriptionId, String planCode, String status, Instant periodEnd,
            boolean cancelAtPeriodEnd, Instant trialEnd, boolean hasPaid, Instant eventAt, Instant now) {
        jdbc.sql("""
                UPDATE tenant_subscriptions SET stripe_subscription_id = :sub, plan_code = :plan, status = :status,
                    current_period_end = :end, cancel_at_period_end = :cancel, trial_end = :trialEnd,
                    trial_used = true, has_paid = :paid, last_event_at = :event, updated_at = :now""")
                .param("sub", subscriptionId).param("plan", planCode).param("status", status)
                .param("end", periodEnd == null ? null : Sql.ts(periodEnd)).param("cancel", cancelAtPeriodEnd)
                .param("trialEnd", trialEnd == null ? null : Sql.ts(trialEnd)).param("paid", hasPaid)
                .param("event", Sql.ts(eventAt)).param("now", Sql.ts(now)).update();
    }

    public void setTenantPlan(String planCode, Instant now) {
        jdbc.sql("UPDATE tenants SET plan_code = :plan, updated_at = :now")
                .param("plan", planCode).param("now", Sql.ts(now)).update();
    }

    public Optional<UUID> tenantOfCustomer(String customerId) {
        return jdbc.sql("SELECT billing_lookup_tenant(:customer)").param("customer", customerId)
                .query(UUID.class).list().stream().filter(Objects::nonNull).findFirst();
    }

    public boolean eventProcessed(String eventId) {
        return jdbc.sql("SELECT EXISTS (SELECT 1 FROM stripe_webhook_events WHERE event_id = :id)")
                .param("id", eventId).query(Boolean.class).single();
    }

    public void recordEvent(String eventId, String type, UUID tenantId, String outcome, Instant now) {
        jdbc.sql("""
                INSERT INTO stripe_webhook_events (event_id, type, tenant_id, outcome, received_at)
                VALUES (:id, :type, :tenant, :outcome, :now)""")
                .param("id", eventId).param("type", type).param("tenant", tenantId).param("outcome", outcome)
                .param("now", Sql.ts(now)).update();
    }
}

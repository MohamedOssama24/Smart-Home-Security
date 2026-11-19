package com.shsc.billing;

import java.net.URI;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.billing.BillingRepository.PlanInfo;
import com.shsc.billing.BillingRepository.Subscription;
import com.shsc.billing.StripeClient.StripeException;
import com.shsc.billing.StripeWebhookVerifier.InvalidSignatureException;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.shared.config.ShscProperties;
import com.shsc.shared.persistence.TenantScope;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;
import com.shsc.tenancy.TenantRepository;
import com.shsc.tenancy.TenantRepository.Tenant;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * SaaS subscriptions with Stripe (ADR-072). The dashboard only starts a Stripe Checkout or opens
 * the Billing Portal; the subscription state comes exclusively from signed webhooks, which set the
 * effective plan of the tenant ({@code tenants.plan_code}). Card data never reaches the backend.
 */
@Service
public class BillingService {

    public record Overview(boolean enabled, String tenantType, String currentPlan, Subscription subscription,
            List<PlanInfo> plans, int trialDays) {
    }

    /** Stripe limit for trial_period_days. */
    static final int MAX_TRIAL_DAYS = 730;

    /**
     * Statuses in which the paid plan applies. past_due (grace while Stripe retries) only after the
     * subscription has been paid at least once: a failed first payment at the end of a trial applies FREE.
     */
    static final Set<String> ENTITLED = Set.of("active", "trialing", "past_due");
    static final Set<String> TERMINAL = Set.of("canceled", "incomplete_expired");
    static final Set<String> STATUSES = Set.of("incomplete", "incomplete_expired", "trialing", "active",
            "past_due", "canceled", "unpaid", "paused");
    static final String FREE = "FREE";

    private static final Logger LOG = LoggerFactory.getLogger(BillingService.class);

    private final BillingRepository billing;
    private final TenantRepository tenants;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final TenantScope tenantScope;
    private final TransactionTemplate tx;
    private final JsonMapper json;
    private final Clock clock;
    private final String baseUrl;
    private final Map<String, String> priceByPlan;
    private final boolean allowLive;
    private final int trialDays;
    private final StripeClient stripe;
    private final StripeWebhookVerifier verifier;

    public BillingService(BillingRepository billing, TenantRepository tenants, AccessPolicy access, AuditLog audit,
            TenantScope tenantScope, TransactionTemplate tx, JsonMapper json, Clock clock, ShscProperties properties,
            @Value("${shsc.billing.stripe.secret-key:}") String secretKey,
            @Value("${shsc.billing.stripe.webhook-secret:}") String webhookSecret,
            @Value("${shsc.billing.stripe.api-url:https://api.stripe.com}") URI apiUrl,
            @Value("${shsc.billing.stripe.price-plus:}") String pricePlus,
            @Value("${shsc.billing.stripe.price-pro:}") String pricePro,
            @Value("${shsc.billing.stripe.allow-live:false}") boolean allowLive,
            @Value("${shsc.billing.stripe.webhook-tolerance:PT5M}") Duration tolerance,
            @Value("${shsc.billing.stripe.trial-days:0}") int trialDays) {
        if (trialDays < 0 || trialDays > MAX_TRIAL_DAYS) {
            throw new IllegalStateException("shsc.billing.stripe.trial-days must be between 0 and " + MAX_TRIAL_DAYS);
        }
        this.trialDays = trialDays;
        this.billing = billing;
        this.tenants = tenants;
        this.access = access;
        this.audit = audit;
        this.tenantScope = tenantScope;
        this.tx = tx;
        this.json = json;
        this.clock = clock;
        this.baseUrl = properties.publicBaseUrl().toString().replaceAll("/+$", "");
        this.priceByPlan = prices(pricePlus, pricePro);
        this.allowLive = allowLive;
        boolean configured = !secretKey.isBlank() && !webhookSecret.isBlank();
        if (configured && !allowLive && !(secretKey.startsWith("sk_test_") || secretKey.startsWith("rk_test_"))) {
            throw new IllegalStateException("shsc.billing.stripe.secret-key must be a test key unless allow-live=true");
        }
        this.stripe = configured ? new StripeClient(apiUrl, secretKey.strip(), json) : null;
        this.verifier = configured ? new StripeWebhookVerifier(webhookSecret, tolerance) : null;
        LOG.info("Billing {}", configured ? "enabled (Stripe, " + (allowLive ? "live allowed" : "test mode") + ")"
                : "disabled: SHSC_STRIPE_SECRET_KEY / SHSC_STRIPE_WEBHOOK_SECRET not set");
    }

    private static Map<String, String> prices(String plus, String pro) {
        var map = new java.util.HashMap<String, String>();
        if (!plus.isBlank()) {
            map.put("PLUS", plus.strip());
        }
        if (!pro.isBlank()) {
            map.put("PRO", pro.strip());
        }
        return Map.copyOf(map);
    }

    public boolean enabled() {
        return stripe != null;
    }

    // --- dashboard ---------------------------------------------------------------------------

    public Overview overview() {
        return tx.execute(status -> {
            access.requireTenantWide(Permissions.BILLING_MANAGE);
            Tenant tenant = tenants.current().orElseThrow(ApiException::notFound);
            List<PlanInfo> plans = billing.plans().stream()
                    .filter(p -> p.tenantTypes().contains(tenant.type().name()))
                    .filter(p -> FREE.equals(p.code()) || priceByPlan.containsKey(p.code()))
                    .toList();
            Optional<Subscription> subscription = billing.subscription(false);
            return new Overview(enabled(), tenant.type().name(), tenant.planCode(), subscription.orElse(null), plans,
                    enabled() ? trialOffered(subscription) : 0);
        });
    }

    /** One free trial per tenant: only until the tenant has had a Stripe subscription. */
    private int trialOffered(Optional<Subscription> subscription) {
        boolean used = subscription.map(s -> s.trialUsed() || s.subscriptionId() != null).orElse(false);
        return used ? 0 : trialDays;
    }

    /** Creates (once) the Stripe customer of the tenant and a Checkout Session for the plan. */
    public URI checkout(String planCode, ClientInfo client) {
        requireEnabled();
        record Ready(AuthenticatedUser user, String customerId, String priceId, int trialDays) {
        }
        Ready ready = tx.execute(status -> {
            AuthenticatedUser user = access.requireTenantWide(Permissions.BILLING_MANAGE);
            Tenant tenant = tenants.current().orElseThrow(ApiException::notFound);
            PlanInfo plan = billing.plan(planCode).orElse(null);
            String price = priceByPlan.get(planCode);
            if (plan == null || FREE.equals(planCode) || price == null
                    || !plan.tenantTypes().contains(tenant.type().name())) {
                throw ApiException.badRequest("PLAN_NOT_AVAILABLE", "This plan cannot be subscribed.");
            }
            Optional<Subscription> current = billing.subscription(true);
            current.ifPresent(BillingService::requireNoSubscription);
            return new Ready(user, current.map(Subscription::customerId).orElse(null), price, trialOffered(current));
        });
        String customerId = ready.customerId();
        if (customerId == null) {
            String created = callStripe(() -> stripe.createCustomer(ready.user().tenantId()));
            if (!created.matches("cus_[A-Za-z0-9]{1,250}")) {
                throw providerError();
            }
            customerId = tx.execute(status -> {
                billing.insertCustomer(ready.user().tenantId(), created, clock.instant());
                return billing.subscription(false).orElseThrow().customerId();
            });
        }
        String customer = customerId;
        // concurrent checkouts of the tenant are serialized by the row lock; Stripe is asked whether a
        // subscription already exists (also one whose webhook has not arrived yet) and the older open
        // sessions are expired, so at most one checkout can be completed (M18)
        String url = tx.execute(status -> {
            billing.subscription(true).ifPresent(BillingService::requireNoSubscription);
            if (callStripe(() -> stripe.hasOpenSubscription(customer) ? "yes" : "no").equals("yes")) {
                throw subscriptionExists();
            }
            callStripe(() -> Integer.toString(stripe.expireOpenCheckoutSessions(customer)));
            return callStripe(() -> stripe.createCheckoutSession(customer, ready.priceId(),
                    ready.user().tenantId(), planCode, ready.trialDays(), baseUrl + "/billing?checkout=success",
                    baseUrl + "/billing?checkout=cancel"));
        });
        tx.executeWithoutResult(status -> audit.record(AuditEvent.of(AuditAction.BILLING_CHECKOUT_STARTED)
                .tenant(ready.user().tenantId()).user(ready.user().userId()).client(client)
                .target("TENANT", ready.user().tenantId()).detail("plan", planCode)
                .detail("trialDays", Integer.toString(ready.trialDays())).build()));
        return stripeUrl(url);
    }

    /** Billing Portal session: change plan, payment method, invoices, cancellation. */
    public URI portal(ClientInfo client) {
        requireEnabled();
        record Ready(AuthenticatedUser user, String customerId) {
        }
        Ready ready = tx.execute(status -> {
            AuthenticatedUser user = access.requireTenantWide(Permissions.BILLING_MANAGE);
            Subscription s = billing.subscription(false)
                    .orElseThrow(() -> ApiException.conflict("NO_SUBSCRIPTION", "There is no subscription yet."));
            return new Ready(user, s.customerId());
        });
        String url = callStripe(() -> stripe.createPortalSession(ready.customerId(), baseUrl + "/billing"));
        tx.executeWithoutResult(status -> audit.record(AuditEvent.of(AuditAction.BILLING_PORTAL_OPENED)
                .tenant(ready.user().tenantId()).user(ready.user().userId()).client(client)
                .target("TENANT", ready.user().tenantId()).build()));
        return stripeUrl(url);
    }

    // --- webhook ------------------------------------------------------------------------------

    /**
     * Verified, idempotent, tenant-scoped handling of a Stripe event. The tenant is found only from
     * the Stripe customer id stored at checkout (never from metadata in the payload).
     */
    public String webhook(String signature, byte[] payload) {
        if (!enabled()) {
            throw ApiException.notFound();
        }
        try {
            verifier.verify(signature, payload, clock.instant());
        } catch (InvalidSignatureException e) {
            LOG.warn("Stripe webhook rejected: {}", e.getMessage());
            throw ApiException.badRequest("INVALID_SIGNATURE", "The webhook signature is not valid.");
        }
        JsonNode event;
        try {
            event = json.readTree(payload);
        } catch (RuntimeException e) {
            throw ApiException.badRequest("INVALID_EVENT", "The event is not valid JSON.");
        }
        String eventId = event.path("id").asString("");
        String type = event.path("type").asString("");
        long created = event.path("created").asLong(0);
        JsonNode object = event.path("data").path("object");
        if (!eventId.matches("evt_[A-Za-z0-9]{1,250}") || !type.matches("[a-z0-9_.]{1,100}") || created <= 0) {
            throw ApiException.badRequest("INVALID_EVENT", "The event is not valid.");
        }
        if (event.path("livemode").asBoolean(false) && !allowLive) {
            LOG.warn("Stripe event {} ignored: live mode not allowed", eventId);
            return "IGNORED";
        }
        if (!type.equals("checkout.session.completed") && !type.startsWith("customer.subscription.")) {
            return "IGNORED";
        }
        String customerId = object.path("customer").asString("");
        Optional<UUID> tenant = customerId.matches("cus_[A-Za-z0-9]{1,250}")
                ? tx.execute(status -> billing.tenantOfCustomer(customerId)) : Optional.empty();
        if (tenant.isEmpty()) {
            LOG.info("Stripe event {} ({}) ignored: unknown customer", eventId, type);
            return "IGNORED";
        }
        UUID tenantId = tenant.get();
        Instant eventAt = Instant.ofEpochSecond(created);
        return tenantScope.callAs(tenantId, () -> tx.execute(status -> {
            Subscription current = billing.subscription(true).orElseThrow();
            if (billing.eventProcessed(eventId)) {
                return "DUPLICATE";
            }
            String outcome = type.equals("checkout.session.completed")
                    ? checkoutCompleted(object)
                    : subscriptionChanged(tenantId, current, object, eventAt, type);
            billing.recordEvent(eventId, type, tenantId, outcome, clock.instant());
            return outcome;
        }));
    }

    private String checkoutCompleted(JsonNode session) {
        String subscriptionId = session.path("subscription").asString("");
        if (!"subscription".equals(session.path("mode").asString("")) || !subscriptionId.matches("sub_[A-Za-z0-9]{1,250}")) {
            return "IGNORED";
        }
        // the state (plan, status) arrives with customer.subscription.* events
        billing.linkSubscription(subscriptionId, clock.instant());
        return "APPLIED";
    }

    private String subscriptionChanged(UUID tenantId, Subscription current, JsonNode sub, Instant eventAt,
            String type) {
        String subscriptionId = sub.path("id").asString("");
        String status = type.equals("customer.subscription.deleted") ? "canceled" : sub.path("status").asString("");
        if (!subscriptionId.matches("sub_[A-Za-z0-9]{1,250}") || !STATUSES.contains(status)) {
            return "IGNORED";
        }
        if (current.lastEventAt() != null && eventAt.isBefore(current.lastEventAt())) {
            return "STALE";
        }
        // a terminal event of another (older) subscription must not cancel the current one, and a second
        // subscription never replaces a current one that is not terminated (M18, double checkout)
        if (current.subscriptionId() != null && !current.subscriptionId().equals(subscriptionId)) {
            boolean currentOpen = current.status() == null || !TERMINAL.contains(current.status());
            if (!ENTITLED.contains(status)) {
                return "IGNORED";
            }
            if (currentOpen) {
                LOG.error("Tenant {} has a second Stripe subscription {}: not applied, cancel it in Stripe",
                        tenantId, subscriptionId);
                audit.record(AuditEvent.of(AuditAction.SUBSCRIPTION_CHANGED).tenant(tenantId)
                        .target("TENANT", tenantId).detail("status", status).detail("duplicate", "true").build());
                return "IGNORED";
            }
        }
        JsonNode item = sub.path("items").path("data").path(0);
        String priceId = item.path("price").path("id").asString("");
        String planCode = priceByPlan.entrySet().stream().filter(e -> e.getValue().equals(priceId))
                .map(Map.Entry::getKey).findFirst().orElse(null);
        long periodEnd = sub.path("current_period_end").asLong(item.path("current_period_end").asLong(0));
        long trialEnd = sub.path("trial_end").asLong(0);
        // paid at least once: sticky for the same subscription, reset for a new one
        boolean hasPaid = "active".equals(status)
                || (current.hasPaid() && subscriptionId.equals(current.subscriptionId()));
        boolean entitled = ENTITLED.contains(status) && (!"past_due".equals(status) || hasPaid);
        Instant now = clock.instant();
        billing.updateSubscription(subscriptionId, planCode, status, periodEnd > 0 ? Instant.ofEpochSecond(periodEnd)
                : null, sub.path("cancel_at_period_end").asBoolean(false),
                trialEnd > 0 ? Instant.ofEpochSecond(trialEnd) : null, hasPaid, eventAt, now);

        Tenant tenant = tenants.lockCurrent().orElseThrow();
        String effective = FREE;
        if (planCode != null && entitled) {
            boolean allowed = billing.plan(planCode).map(p -> p.tenantTypes().contains(tenant.type().name()))
                    .orElse(false);
            if (allowed) {
                effective = planCode;
            } else {
                LOG.warn("Plan {} not allowed for tenant type {}: FREE applied", planCode, tenant.type());
            }
        } else if (planCode == null && ENTITLED.contains(status)) {
            LOG.warn("Subscription {} has an unknown price: FREE applied", subscriptionId);
        }
        if (!effective.equals(tenant.planCode())) {
            billing.setTenantPlan(effective, now);
        }
        audit.record(AuditEvent.of(AuditAction.SUBSCRIPTION_CHANGED).tenant(tenantId).target("TENANT", tenantId)
                .detail("status", status).detail("from", tenant.planCode()).detail("to", effective).build());
        return "APPLIED";
    }

    // --- helpers ------------------------------------------------------------------------------

    private static void requireNoSubscription(Subscription s) {
        boolean open = s.status() != null ? !TERMINAL.contains(s.status()) : s.subscriptionId() != null;
        if (open) {
            throw subscriptionExists();
        }
    }

    private static ApiException subscriptionExists() {
        return ApiException.conflict("SUBSCRIPTION_EXISTS",
                "A subscription already exists: change it from the billing portal.");
    }

    private void requireEnabled() {
        if (!enabled()) {
            throw new ApiException(HttpStatus.SERVICE_UNAVAILABLE, "BILLING_DISABLED",
                    "Online subscriptions are not enabled on this installation.");
        }
    }

    private static String callStripe(java.util.function.Supplier<String> call) {
        try {
            return call.get();
        } catch (StripeException e) {
            throw providerError();
        }
    }

    private static ApiException providerError() {
        return new ApiException(HttpStatus.BAD_GATEWAY, "BILLING_PROVIDER_ERROR",
                "The payment provider is not reachable, try again later.");
    }

    /** Only https URLs on the Stripe Checkout / Billing Portal hosts are returned to the browser. */
    private static URI stripeUrl(String url) {
        try {
            URI uri = URI.create(url);
            String host = uri.getHost() == null ? "" : uri.getHost();
            if ("https".equals(uri.getScheme()) && uri.getUserInfo() == null
                    && (host.equals("checkout.stripe.com") || host.equals("billing.stripe.com"))) {
                return uri;
            }
        } catch (IllegalArgumentException e) {
            // fall through
        }
        throw providerError();
    }
}

package com.shsc.billing;

import static org.assertj.core.api.Assertions.assertThat;

import java.awt.image.BufferedImage;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;

import javax.imageio.ImageIO;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.shared.persistence.TenantScope;
import com.shsc.support.ApiClient.Response;
import com.shsc.support.Fixtures;
import com.shsc.support.IntegrationTest;
import com.shsc.support.TestAccounts.Account;
import com.sun.net.httpserver.HttpServer;

/**
 * SaaS billing (Milestone 17) against a local fake of the Stripe API ([MOCK]: no network, no real
 * keys): checkout limited to the plans of the tenant type, signed and idempotent webhooks, tenant
 * found only from the stored Stripe customer, stale and unknown events, downgrade, permissions,
 * isolation between organizations and white label gated by the plan.
 */
class BillingIntegrationTest extends IntegrationTest {

    private static final String WEBHOOK_SECRET = "whsec_MOCK_only_for_tests";
    private static final String PRICE_PLUS = "price_MOCKplus";
    private static final String PRICE_PRO = "price_MOCKpro";
    private static final List<String> STRIPE_CALLS = new CopyOnWriteArrayList<>();
    private static final AtomicInteger CUSTOMERS = new AtomicInteger();
    private static final AtomicInteger SESSIONS = new AtomicInteger();
    private static final Map<String, List<String>> OPEN_SESSIONS = new java.util.concurrent.ConcurrentHashMap<>();
    private static final Map<String, List<String>> STRIPE_SUBSCRIPTIONS = new java.util.concurrent.ConcurrentHashMap<>();
    private static final HttpServer STRIPE = fakeStripe();

    @DynamicPropertySource
    static void stripe(DynamicPropertyRegistry registry) {
        registry.add("shsc.billing.stripe.secret-key", () -> "sk_test_MOCK");
        registry.add("shsc.billing.stripe.webhook-secret", () -> WEBHOOK_SECRET);
        registry.add("shsc.billing.stripe.price-plus", () -> PRICE_PLUS);
        registry.add("shsc.billing.stripe.price-pro", () -> PRICE_PRO);
        registry.add("shsc.billing.stripe.api-url", () -> "http://127.0.0.1:" + STRIPE.getAddress().getPort());
        registry.add("shsc.billing.stripe.trial-days", () -> "14");
    }

    @AfterAll
    static void stop() {
        STRIPE.stop(0);
    }

    @Autowired
    private Fixtures fixtures;

    @Autowired
    private TenantScope tenantScope;

    @Autowired
    private TransactionTemplate tx;

    @Autowired
    private JdbcClient jdbc;

    private final StripeWebhookVerifier signer = new StripeWebhookVerifier(WEBHOOK_SECRET, Duration.ofMinutes(5));
    private final AtomicInteger events = new AtomicInteger();

    @Test
    void subscriptionsComeOnlyFromSignedWebhooksOfTheRightTenant() throws Exception {
        Account home = accounts().individual();
        Response overview = home.api().get("/api/v1/billing");
        assertThat(overview.status()).as(overview.body()).isEqualTo(200);
        assertThat(overview.json().path("enabled").asBoolean()).isTrue();
        assertThat(overview.text("currentPlan")).isEqualTo("FREE");
        assertThat(codes(overview)).containsExactly("FREE", "PLUS");

        // only the paid plans of the tenant type
        assertThat(checkout(home, "PRO").text("code")).isEqualTo("PLAN_NOT_AVAILABLE");
        assertThat(checkout(home, "FREE").status()).isEqualTo(400);
        Response session = checkout(home, "PLUS");
        assertThat(session.status()).as(session.body()).isEqualTo(200);
        assertThat(session.text("url")).startsWith("https://checkout.stripe.com/");
        assertThat(STRIPE_CALLS).anyMatch(c -> c.startsWith("/v1/checkout/sessions") && c.contains(PRICE_PLUS)
                && c.contains("mode=subscription"));
        String customerA = customer(home);
        assertThat(customerA).startsWith("cus_MOCK");

        // signature: wrong secret, old timestamp, tampered body
        String created = subscriptionEvent("customer.subscription.created", customerA, "sub_MOCKa", "active",
                PRICE_PLUS, Instant.now());
        assertThat(webhook(created, "t=1,v1=" + "0".repeat(64)).text("code")).isEqualTo("INVALID_SIGNATURE");
        long old = Instant.now().minusSeconds(600).getEpochSecond();
        assertThat(webhook(created, signer.header(old, bytes(created))).status()).isEqualTo(400);
        assertThat(rawWebhook(created, signer.header(now(), bytes(created.replace("active", "trialing"))))
                .status()).isEqualTo(400);
        assertThat(plan(home)).isEqualTo("FREE");

        // valid event: plan applied once, the replay is a no-op
        assertThat(signed(created).text("outcome")).isEqualTo("APPLIED");
        assertThat(plan(home)).isEqualTo("PLUS");
        assertThat(home.api().get("/api/v1/tenants/current").json().path("plan").path("maxHomes").asInt()).isEqualTo(5);
        assertThat(signed(created).text("outcome")).isEqualTo("DUPLICATE");
        assertThat(count(home, "SELECT count(*) FROM audit_logs WHERE action = 'SUBSCRIPTION_CHANGED'")).isEqualTo(1);
        Response billing = home.api().get("/api/v1/billing");
        assertThat(billing.json().path("subscription").path("status").asString()).isEqualTo("active");
        assertThat(billing.body()).doesNotContain("cus_", "sub_");

        // one subscription per tenant; changes go through the portal
        assertThat(checkout(home, "PLUS").text("code")).isEqualTo("SUBSCRIPTION_EXISTS");
        Response portal = home.api().post("/api/v1/billing/portal", Map.of());
        assertThat(portal.text("url")).startsWith("https://billing.stripe.com/");

        // out-of-order and unknown events change nothing
        String stale = subscriptionEvent("customer.subscription.updated", customerA, "sub_MOCKa", "canceled",
                PRICE_PLUS, Instant.now().minusSeconds(60));
        assertThat(signed(stale).text("outcome")).isEqualTo("STALE");
        String unknown = subscriptionEvent("customer.subscription.updated", "cus_MOCKnobody", "sub_MOCKx", "active",
                PRICE_PLUS, Instant.now());
        assertThat(signed(unknown).text("outcome")).isEqualTo("IGNORED");
        assertThat(plan(home)).isEqualTo("PLUS");

        // second organization: its own customer; the tenant is never taken from the payload metadata
        Account org = accounts().business("Installatore MOCK");
        assertThat(codes(org.api().get("/api/v1/billing"))).containsExactly("FREE", "PRO");
        assertThat(org.api().put("/api/v1/branding", Map.of("displayName", "Installatore MOCK")).text("code"))
                .isEqualTo("PLAN_FEATURE_UNAVAILABLE");
        assertThat(checkout(org, "PRO").status()).isEqualTo(200);
        String customerB = customer(org);
        assertThat(customerB).isNotEqualTo(customerA);
        // a plan of another tenant type is not applied
        String wrongType = subscriptionEvent("customer.subscription.created", customerB, "sub_MOCKb", "active",
                PRICE_PLUS, Instant.now()).replace("\"metadata\":{}", "\"metadata\":{\"tenant_id\":\""
                        + home.tenantId() + "\"}");
        assertThat(signed(wrongType).text("outcome")).isEqualTo("APPLIED");
        assertThat(plan(org)).isEqualTo("FREE");
        assertThat(plan(home)).isEqualTo("PLUS");
        signed(subscriptionEvent("customer.subscription.updated", customerB, "sub_MOCKb", "active", PRICE_PRO,
                Instant.now().plusSeconds(1)));
        assertThat(plan(org)).isEqualTo("PRO");
        assertThat(plan(home)).isEqualTo("PLUS");

        // white label: PRO only, per tenant, validated logo
        Response branded = org.api().put("/api/v1/branding",
                Map.of("displayName", "Installatore MOCK", "primaryColor", "#0A5C8F", "supportEmail", "help@mock.test"));
        assertThat(branded.status()).as(branded.body()).isEqualTo(200);
        assertThat(branded.text("primaryColor")).isEqualTo("#0a5c8f");
        assertThat(org.api().put("/api/v1/branding", Map.of("primaryColor", "red")).status()).isEqualTo(400);
        assertThat(org.api().put("/api/v1/branding", Map.of("displayName", "a‮b")).status()).isEqualTo(400);
        byte[] png = png();
        assertThat(upload(org, png, "image/png").statusCode()).isEqualTo(200);
        assertThat(upload(org, "<svg onload=alert(1)>".getBytes(StandardCharsets.UTF_8), "image/svg+xml").statusCode())
                .isEqualTo(415);
        assertThat(upload(org, "not an image".getBytes(StandardCharsets.UTF_8), "image/png").statusCode()).isEqualTo(400);
        assertThat(upload(org, png, "image/jpeg").statusCode()).isEqualTo(400);
        HttpResponse<byte[]> logo = download(org);
        assertThat(logo.statusCode()).isEqualTo(200);
        assertThat(logo.body()).isEqualTo(png);
        assertThat(logo.headers().firstValue("x-content-type-options")).contains("nosniff");
        assertThat(home.api().get("/api/v1/branding").json().path("available").asBoolean()).isFalse();
        assertThat(home.api().get("/api/v1/branding").body()).doesNotContain("Installatore");
        assertThat(download(home).statusCode()).isEqualTo(404);
        Account technician = fixtures.addUser(accounts(), client(), org, "TECHNICIAN", ScopeType.TENANT, null);
        assertThat(technician.api().get("/api/v1/branding").text("displayName")).isEqualTo("Installatore MOCK");
        assertThat(technician.api().put("/api/v1/branding", Map.of("displayName", "x")).status()).isEqualTo(403);
        assertThat(technician.api().get("/api/v1/billing").status()).isEqualTo(403);
        assertThat(technician.api().post("/api/v1/billing/checkout", Map.of("planCode", "PRO")).status())
                .isEqualTo(403);

        // cancellation: back to FREE, the branding is kept but no longer applied
        signed(subscriptionEvent("customer.subscription.deleted", customerB, "sub_MOCKb", "canceled", PRICE_PRO,
                Instant.now().plusSeconds(2)));
        assertThat(plan(org)).isEqualTo("FREE");
        assertThat(org.api().get("/api/v1/branding").json().path("available").asBoolean()).isFalse();
        assertThat(download(org).statusCode()).isEqualTo(404);
        assertThat(plan(home)).isEqualTo("PLUS");

        // other event types are acknowledged and ignored; the endpoint is not reachable without a signature
        assertThat(signed(event("invoice.paid", customerA, "{\"customer\":\"" + customerA + "\"}", Instant.now()))
                .text("outcome")).isEqualTo("IGNORED");
        assertThat(rawWebhook("{}", null).status()).isEqualTo(400);
        Account reader = fixtures.addUser(accounts(), client(), home, "READ_ONLY", ScopeType.TENANT, null);
        assertThat(reader.api().get("/api/v1/billing").status()).isEqualTo(403);
    }

    @Test
    void freeTrialIsOfferedOnceAndTheEndOfTheTrialFollowsThePayment() {
        // trial ended with a successful payment: trialing -> active keeps the plan
        Account paid = accounts().individual();
        assertThat(paid.api().get("/api/v1/billing").json().path("trialDays").asInt()).isEqualTo(14);
        int calls = STRIPE_CALLS.size();
        assertThat(checkout(paid, "PLUS").status()).isEqualTo(200);
        String form = decoded(STRIPE_CALLS.get(STRIPE_CALLS.size() - 1));
        assertThat(STRIPE_CALLS.size()).isGreaterThan(calls);
        assertThat(form).startsWith("/v1/checkout/sessions").contains("subscription_data[trial_period_days]=14",
                "subscription_data[trial_settings][end_behavior][missing_payment_method]=cancel",
                "payment_method_collection=always");
        // an abandoned checkout does not consume the trial
        assertThat(paid.api().get("/api/v1/billing").json().path("trialDays").asInt()).isEqualTo(14);
        String customer = customer(paid);
        Instant start = Instant.now();
        Instant trialEnd = start.plusSeconds(14 * 86400).truncatedTo(java.time.temporal.ChronoUnit.SECONDS);
        signed(trial(subscriptionEvent("customer.subscription.created", customer, "sub_MOCKtrialA", "trialing",
                PRICE_PLUS, start), trialEnd));
        assertThat(plan(paid)).isEqualTo("PLUS");
        Response billing = paid.api().get("/api/v1/billing");
        assertThat(billing.json().path("subscription").path("status").asString()).isEqualTo("trialing");
        assertThat(Instant.parse(billing.json().path("subscription").path("trialEnd").asString())).isEqualTo(trialEnd);
        assertThat(billing.json().path("trialDays").asInt()).isZero();
        signed(subscriptionEvent("customer.subscription.updated", customer, "sub_MOCKtrialA", "active", PRICE_PLUS,
                start.plusSeconds(1)));
        assertThat(plan(paid)).isEqualTo("PLUS");
        // a later failed renewal of a paid subscription: grace while Stripe retries
        signed(subscriptionEvent("customer.subscription.updated", customer, "sub_MOCKtrialA", "past_due", PRICE_PLUS,
                start.plusSeconds(2)));
        assertThat(plan(paid)).isEqualTo("PLUS");

        // trial ended with a failed payment: FREE at once, data kept, FREE limits on new operations
        Account failed = accounts().individual();
        assertThat(checkout(failed, "PLUS").status()).isEqualTo(200);
        String customerF = customer(failed);
        signed(trial(subscriptionEvent("customer.subscription.created", customerF, "sub_MOCKtrialF", "trialing",
                PRICE_PLUS, start), trialEnd));
        assertThat(plan(failed)).isEqualTo("PLUS");
        int homes = failed.api().get("/api/v1/homes").json().size();
        for (int i = homes; i < 3; i++) {
            Fixtures.createHome(failed, "Casa trial MOCK " + i);
        }
        signed(subscriptionEvent("customer.subscription.updated", customerF, "sub_MOCKtrialF", "past_due", PRICE_PLUS,
                start.plusSeconds(1)));
        assertThat(plan(failed)).isEqualTo("FREE");
        assertThat(failed.api().get("/api/v1/homes").json().size()).isEqualTo(3);
        assertThat(failed.api().post("/api/v1/homes", Map.of("name", "Casa oltre il limite")).text("code"))
                .isEqualTo("PLAN_LIMIT_REACHED");
        // Stripe collects the retry: the paid plan comes back
        signed(subscriptionEvent("customer.subscription.updated", customerF, "sub_MOCKtrialF", "active", PRICE_PLUS,
                start.plusSeconds(2)));
        assertThat(plan(failed)).isEqualTo("PLUS");
        assertThat(Fixtures.createHome(failed, "Casa dopo il pagamento")).isNotBlank();
        // retries exhausted / no payment method at the end of the trial: canceled -> FREE
        signed(subscriptionEvent("customer.subscription.deleted", customerF, "sub_MOCKtrialF", "canceled", PRICE_PLUS,
                start.plusSeconds(3)));
        assertThat(plan(failed)).isEqualTo("FREE");
        assertThat(failed.api().get("/api/v1/homes").json().size()).isEqualTo(4);

        // one trial per tenant: a new checkout has no trial
        assertThat(failed.api().get("/api/v1/billing").json().path("trialDays").asInt()).isZero();
        assertThat(checkout(failed, "PLUS").status()).isEqualTo(200);
        assertThat(decoded(STRIPE_CALLS.get(STRIPE_CALLS.size() - 1))).startsWith("/v1/checkout/sessions")
                .doesNotContain("trial_period_days");
        assertThat(count(failed, "SELECT count(*) FROM audit_logs WHERE action = 'BILLING_CHECKOUT_STARTED'"
                + " AND details ->> 'trialDays' = '0'")).isEqualTo(1);
    }

    @Test
    void concurrentCheckoutsLeaveOneOpenSessionAndASecondSubscriptionIsNeverApplied() throws Exception {
        Account tenant = accounts().individual();
        assertThat(checkout(tenant, "PLUS").status()).isEqualTo(200);
        String customer = customer(tenant);
        // parallel clicks: serialized by the row lock, older open sessions expired -> one can be paid
        java.util.concurrent.ExecutorService pool = java.util.concurrent.Executors.newFixedThreadPool(5);
        try {
            List<java.util.concurrent.Future<Integer>> results = new java.util.ArrayList<>();
            for (int i = 0; i < 5; i++) {
                results.add(pool.submit(() -> checkout(tenant, "PLUS").status()));
            }
            for (var r : results) {
                assertThat(r.get()).isEqualTo(200);
            }
        } finally {
            pool.shutdownNow();
        }
        assertThat(OPEN_SESSIONS.get(customer)).hasSize(1);

        // completed in Stripe but webhook not arrived yet: Stripe is asked, no new checkout
        STRIPE_SUBSCRIPTIONS.put(customer, List.of("trialing"));
        assertThat(checkout(tenant, "PLUS").text("code")).isEqualTo("SUBSCRIPTION_EXISTS");
        assertThat(OPEN_SESSIONS.get(customer)).hasSize(1);
        STRIPE_SUBSCRIPTIONS.put(customer, List.of("canceled", "incomplete_expired"));
        assertThat(checkout(tenant, "PLUS").status()).isEqualTo(200);

        // a second subscription that reached Stripe anyway never replaces the current one
        Instant start = Instant.now();
        signed(subscriptionEvent("customer.subscription.created", customer, "sub_MOCKdupA", "trialing", PRICE_PLUS,
                start));
        Response dup = signed(subscriptionEvent("customer.subscription.created", customer, "sub_MOCKdupB", "trialing",
                PRICE_PLUS, start.plusSeconds(1)));
        assertThat(dup.text("outcome")).isEqualTo("IGNORED");
        assertThat(count(tenant, "SELECT count(*) FROM audit_logs WHERE action = 'SUBSCRIPTION_CHANGED'"
                + " AND details ->> 'duplicate' = 'true'")).isEqualTo(1);
        assertThat(count(tenant, "SELECT count(*) FROM tenant_subscriptions WHERE stripe_subscription_id = 'sub_MOCKdupA'"))
                .isEqualTo(1);
        // once the current one is canceled, a new subscription is applied again
        signed(subscriptionEvent("customer.subscription.deleted", customer, "sub_MOCKdupA", "canceled", PRICE_PLUS,
                start.plusSeconds(2)));
        assertThat(plan(tenant)).isEqualTo("FREE");
        signed(subscriptionEvent("customer.subscription.updated", customer, "sub_MOCKdupB", "active", PRICE_PLUS,
                start.plusSeconds(3)));
        assertThat(plan(tenant)).isEqualTo("PLUS");
    }

    // --- helpers ------------------------------------------------------------------------------

    private static String decoded(String call) {
        return java.net.URLDecoder.decode(call, StandardCharsets.UTF_8);
    }

    private static String trial(String event, Instant trialEnd) {
        return event.replace("\"cancel_at_period_end\":false,",
                "\"cancel_at_period_end\":false,\"trial_end\":" + trialEnd.getEpochSecond() + ",");
    }

    private static List<String> codes(Response r) {
        List<String> codes = new java.util.ArrayList<>();
        r.json().path("plans").forEach(p -> codes.add(p.path("code").asString()));
        return codes;
    }

    private Response checkout(Account who, String plan) {
        return who.api().post("/api/v1/billing/checkout", Map.of("planCode", plan));
    }

    private String plan(Account who) {
        return who.api().get("/api/v1/tenants/current").json().path("plan").path("code").asString();
    }

    private String customer(Account who) {
        AtomicReference<String> id = new AtomicReference<>();
        tenantScope.runAs(who.tenantId(), () -> id.set(tx.execute(s -> jdbc.sql(
                "SELECT stripe_customer_id FROM tenant_subscriptions").query(String.class).single())));
        return id.get();
    }

    private int count(Account who, String sql) {
        AtomicReference<Integer> n = new AtomicReference<>();
        tenantScope.runAs(who.tenantId(), () -> n.set(tx.execute(s -> jdbc.sql(sql).query(Integer.class).single())));
        return n.get();
    }

    private String subscriptionEvent(String type, String customer, String sub, String status, String price,
            Instant created) {
        String object = """
                {"id":"%s","object":"subscription","customer":"%s","status":"%s","cancel_at_period_end":false,\
                "metadata":{},"items":{"data":[{"price":{"id":"%s"},"current_period_end":%d}]}}"""
                .formatted(sub, customer, status, price, created.plusSeconds(30 * 86400).getEpochSecond());
        return event(type, customer, object, created);
    }

    private String event(String type, String customer, String object, Instant created) {
        return """
                {"id":"evt_MOCK%d%d","object":"event","type":"%s","created":%d,"livemode":false,\
                "data":{"object":%s}}""".formatted(System.nanoTime(), events.incrementAndGet(), type,
                created.getEpochSecond(), object);
    }

    private Response signed(String payload) {
        Response r = webhook(payload, signer.header(now(), bytes(payload)));
        assertThat(r.status()).as(r.body()).isEqualTo(200);
        return r;
    }

    private Response webhook(String payload, String signature) {
        return rawWebhook(payload, signature);
    }

    private Response rawWebhook(String payload, String signature) {
        return client().send("POST", "/api/v1/billing/stripe/webhook", payload,
                signature == null ? Map.of() : Map.of("Stripe-Signature", signature));
    }

    private static long now() {
        return Instant.now().getEpochSecond();
    }

    private static byte[] bytes(String s) {
        return s.getBytes(StandardCharsets.UTF_8);
    }

    private HttpResponse<String> upload(Account who, byte[] body, String type) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/v1/branding/logo"))
                .header("Authorization", "Bearer " + who.accessToken()).header("Content-Type", type)
                .PUT(HttpRequest.BodyPublishers.ofByteArray(body)).build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<byte[]> download(Account who) throws Exception {
        HttpRequest request = HttpRequest.newBuilder(URI.create("http://127.0.0.1:" + port + "/api/v1/branding/logo"))
                .header("Authorization", "Bearer " + who.accessToken()).GET().build();
        return HttpClient.newHttpClient().send(request, HttpResponse.BodyHandlers.ofByteArray());
    }

    private static byte[] png() throws IOException {
        BufferedImage image = new BufferedImage(16, 16, BufferedImage.TYPE_INT_RGB);
        image.setRGB(3, 3, 0x0a5c8f);
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ImageIO.write(image, "png", out);
        return out.toByteArray();
    }

    /** Fake Stripe API: checks the test key and answers like Stripe with fixed MOCK ids and URLs. */
    private static HttpServer fakeStripe() {
        try {
            HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.createContext("/", exchange -> {
                String path = exchange.getRequestURI().getPath();
                String query = exchange.getRequestURI().getQuery();
                String body = new String(exchange.getRequestBody().readAllBytes(), StandardCharsets.UTF_8);
                STRIPE_CALLS.add(path + "?" + (query != null ? query : body));
                String customerParam = java.util.Arrays.stream((query != null ? query : body).split("&"))
                        .filter(p -> p.startsWith("customer=")).map(p -> p.substring(9)).findFirst().orElse("");
                String auth = exchange.getRequestHeaders().getFirst("Authorization");
                String response;
                int status = 200;
                if (!"Bearer sk_test_MOCK".equals(auth)) {
                    status = 401;
                    response = "{\"error\":{\"type\":\"invalid_request_error\"}}";
                } else if (path.equals("/v1/customers")
                        && exchange.getRequestHeaders().getFirst("Idempotency-Key") != null) {
                    response = "{\"id\":\"cus_MOCK" + CUSTOMERS.incrementAndGet() + "\"}";
                } else if (path.equals("/v1/subscriptions") && query != null) {
                    // [MOCK] subscriptions Stripe already has for the customer (set by the test)
                    response = "{\"object\":\"list\",\"has_more\":false,\"data\":["
                            + STRIPE_SUBSCRIPTIONS.getOrDefault(customerParam, List.of()).stream()
                                    .map(s -> "{\"status\":\"" + s + "\"}").collect(java.util.stream.Collectors.joining(","))
                            + "]}";
                } else if (path.equals("/v1/checkout/sessions") && query != null) {
                    response = "{\"object\":\"list\",\"has_more\":false,\"data\":["
                            + OPEN_SESSIONS.getOrDefault(customerParam, List.of()).stream()
                                    .map(s -> "{\"id\":\"" + s + "\"}").collect(java.util.stream.Collectors.joining(","))
                            + "]}";
                } else if (path.matches("/v1/checkout/sessions/cs_test_MOCK\\d+/expire")) {
                    String id = path.split("/")[4];
                    OPEN_SESSIONS.values().forEach(l -> l.remove(id));
                    response = "{\"id\":\"" + id + "\",\"status\":\"expired\"}";
                } else if (path.equals("/v1/checkout/sessions")) {
                    String id = "cs_test_MOCK" + SESSIONS.incrementAndGet();
                    OPEN_SESSIONS.computeIfAbsent(customerParam, c -> new java.util.concurrent.CopyOnWriteArrayList<>())
                            .add(id);
                    response = "{\"id\":\"" + id + "\",\"url\":\"https://checkout.stripe.com/c/pay/" + id + "\"}";
                } else if (path.equals("/v1/billing_portal/sessions")) {
                    response = "{\"id\":\"bps_MOCK\",\"url\":\"https://billing.stripe.com/p/session/test_MOCK\"}";
                } else {
                    status = 404;
                    response = "{\"error\":{\"type\":\"invalid_request_error\"}}";
                }
                byte[] bytes = response.getBytes(StandardCharsets.UTF_8);
                exchange.getResponseHeaders().add("Content-Type", "application/json");
                exchange.sendResponseHeaders(status, bytes.length);
                exchange.getResponseBody().write(bytes);
                exchange.close();
            });
            server.start();
            return server;
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }
}

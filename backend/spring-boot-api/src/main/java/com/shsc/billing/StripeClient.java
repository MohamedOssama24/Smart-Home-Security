package com.shsc.billing;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Minimal Stripe REST client (JDK {@link HttpClient}, form-encoded requests; no Stripe SDK, ADR-072).
 * Calls: create customer, create Checkout Session (subscription), create Billing Portal session; since
 * M18 also list subscriptions and expire open Checkout Sessions of the customer (double checkout). The secret key is sent as bearer token and never logged; no redirects, no proxy.
 */
public class StripeClient {

    public static final class StripeException extends RuntimeException {
        StripeException(String message) {
            super(message);
        }
    }

    private static final Logger LOG = LoggerFactory.getLogger(StripeClient.class);
    private static final int MAX_RESPONSE = 256 * 1024;

    private final URI apiUrl;
    private final String secretKey;
    private final JsonMapper json;
    private final HttpClient http;

    public StripeClient(URI apiUrl, String secretKey, JsonMapper json) {
        this.apiUrl = apiUrl;
        this.secretKey = secretKey;
        this.json = json;
        this.http = HttpClient.newBuilder()
                .followRedirects(HttpClient.Redirect.NEVER)
                .proxy(HttpClient.Builder.NO_PROXY)
                .connectTimeout(Duration.ofSeconds(5))
                .build();
    }

    /** One customer per tenant: the idempotency key makes concurrent first checkouts share it. */
    public String createCustomer(UUID tenantId) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("metadata[tenant_id]", tenantId.toString());
        return post("/v1/customers", form, "shsc-customer-" + tenantId).path("id").asString("");
    }

    public String createCheckoutSession(String customerId, String priceId, UUID tenantId, String planCode,
            int trialDays, String successUrl, String cancelUrl) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("mode", "subscription");
        form.put("customer", customerId);
        form.put("client_reference_id", tenantId.toString());
        form.put("line_items[0][price]", priceId);
        form.put("line_items[0][quantity]", "1");
        if (trialDays > 0) {
            // card collected at checkout (payment_method_collection=always); at the end of the trial Stripe
            // charges it: paid -> active, failed -> past_due/unpaid/canceled; no card -> canceled
            form.put("payment_method_collection", "always");
            form.put("subscription_data[trial_period_days]", Integer.toString(trialDays));
            form.put("subscription_data[trial_settings][end_behavior][missing_payment_method]", "cancel");
        }
        form.put("subscription_data[metadata][tenant_id]", tenantId.toString());
        form.put("subscription_data[metadata][plan]", planCode);
        form.put("success_url", successUrl);
        form.put("cancel_url", cancelUrl);
        return post("/v1/checkout/sessions", form, null).path("url").asString("");
    }

    public String createPortalSession(String customerId, String returnUrl) {
        Map<String, String> form = new LinkedHashMap<>();
        form.put("customer", customerId);
        form.put("return_url", returnUrl);
        return post("/v1/billing_portal/sessions", form, null).path("url").asString("");
    }

    /**
     * True when Stripe already has a not terminated subscription of the customer (also one whose
     * webhook has not arrived yet): authoritative check against a second checkout.
     */
    public boolean hasOpenSubscription(String customerId) {
        JsonNode list = get("/v1/subscriptions?status=all&limit=100&customer=" + encode(customerId));
        if (list.path("has_more").asBoolean(false)) {
            return true;
        }
        for (JsonNode sub : list.path("data")) {
            String status = sub.path("status").asString("");
            if (!status.equals("canceled") && !status.equals("incomplete_expired")) {
                return true;
            }
        }
        return false;
    }

    /** Expires the open Checkout Sessions of the customer, so only the newest one can be completed. */
    public int expireOpenCheckoutSessions(String customerId) {
        JsonNode list = get("/v1/checkout/sessions?status=open&limit=100&customer=" + encode(customerId));
        int expired = 0;
        for (JsonNode session : list.path("data")) {
            String id = session.path("id").asString("");
            if (id.matches("cs_[A-Za-z0-9_]{1,250}")) {
                post("/v1/checkout/sessions/" + id + "/expire", Map.of(), null);
                expired++;
            }
        }
        return expired;
    }

    private JsonNode get(String pathAndQuery) {
        return send(HttpRequest.newBuilder(apiUrl.resolve(pathAndQuery)).GET(), pathAndQuery.split("\\?")[0]);
    }

    private JsonNode post(String path, Map<String, String> form, String idempotencyKey) {
        String body = form.entrySet().stream()
                .map(e -> encode(e.getKey()) + "=" + encode(e.getValue()))
                .collect(Collectors.joining("&"));
        HttpRequest.Builder request = HttpRequest.newBuilder(apiUrl.resolve(path))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(body));
        if (idempotencyKey != null) {
            request.header("Idempotency-Key", idempotencyKey);
        }
        return send(request, path);
    }

    private JsonNode send(HttpRequest.Builder request, String path) {
        request.timeout(Duration.ofSeconds(20)).header("Authorization", "Bearer " + secretKey);
        try {
            HttpResponse<byte[]> response = http.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
            byte[] bytes = response.body();
            if (bytes.length > MAX_RESPONSE) {
                throw new StripeException("response too large");
            }
            if (response.statusCode() / 100 != 2) {
                // only the Stripe error type/code is logged (no key, no request body)
                JsonNode error = safeParse(bytes).path("error");
                LOG.warn("Stripe {} failed: HTTP {} {} {}", path, response.statusCode(),
                        error.path("type").asString(""), error.path("code").asString(""));
                throw new StripeException("HTTP " + response.statusCode());
            }
            return json.readTree(bytes);
        } catch (IOException e) {
            throw new StripeException(e.getClass().getSimpleName());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new StripeException("interrupted");
        }
    }

    private JsonNode safeParse(byte[] bytes) {
        try {
            return json.readTree(bytes);
        } catch (RuntimeException e) {
            return json.createObjectNode();
        }
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}

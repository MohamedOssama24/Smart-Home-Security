package com.shsc.billing;

import java.net.URI;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.billing.BillingRepository.PlanInfo;
import com.shsc.billing.BillingService.Overview;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

/** Subscription of the tenant (Stripe Checkout / Billing Portal) and the Stripe webhook. */
@RestController
public class BillingController {

    public record SubscriptionResponse(String planCode, String status, Instant currentPeriodEnd,
            boolean cancelAtPeriodEnd, Instant trialEnd) {
    }

    /** trialDays: free trial offered to this tenant at checkout (0 = none: disabled or already used). */
    public record BillingResponse(boolean enabled, String tenantType, String currentPlan,
            SubscriptionResponse subscription, List<PlanInfo> plans, int trialDays) {
    }

    public record CheckoutRequest(@NotBlank @Pattern(regexp = "^[A-Z_]{2,30}$") String planCode) {
    }

    public record RedirectResponse(URI url) {
    }

    static final int MAX_WEBHOOK_BYTES = 256 * 1024;

    private final BillingService billing;

    public BillingController(BillingService billing) {
        this.billing = billing;
    }

    @GetMapping("/api/v1/billing")
    public BillingResponse overview() {
        Overview o = billing.overview();
        var s = o.subscription();
        // Stripe ids stay on the server
        SubscriptionResponse sub = s == null || s.status() == null ? null
                : new SubscriptionResponse(s.planCode(), s.status(), s.currentPeriodEnd(), s.cancelAtPeriodEnd(),
                        s.trialEnd());
        return new BillingResponse(o.enabled(), o.tenantType(), o.currentPlan(), sub, o.plans(), o.trialDays());
    }

    @PostMapping("/api/v1/billing/checkout")
    public RedirectResponse checkout(@Valid @RequestBody CheckoutRequest request, HttpServletRequest http) {
        return new RedirectResponse(billing.checkout(request.planCode(), ClientInfo.from(http)));
    }

    @PostMapping("/api/v1/billing/portal")
    public RedirectResponse portal(HttpServletRequest http) {
        return new RedirectResponse(billing.portal(ClientInfo.from(http)));
    }

    /** Public endpoint: authenticated by the Stripe signature of the raw body. */
    @PostMapping("/api/v1/billing/stripe/webhook")
    public Map<String, String> webhook(@RequestHeader(value = "Stripe-Signature", required = false) String signature,
            @RequestBody(required = false) byte[] payload) {
        if (payload == null || payload.length == 0) {
            throw ApiException.badRequest("INVALID_EVENT", "Empty event.");
        }
        if (payload.length > MAX_WEBHOOK_BYTES) {
            throw new ApiException(HttpStatus.CONTENT_TOO_LARGE, "PAYLOAD_TOO_LARGE", "The event is too large.");
        }
        return Map.of("outcome", billing.webhook(signature, payload));
    }
}

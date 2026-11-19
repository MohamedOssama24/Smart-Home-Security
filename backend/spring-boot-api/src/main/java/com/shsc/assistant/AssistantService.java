package com.shsc.assistant;

import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayDeque;
import java.util.Deque;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.assistant.AssistantFacts.Fact;
import com.shsc.assistant.AssistantFacts.Finding;
import com.shsc.assistant.AssistantFacts.Device;
import com.shsc.assistant.AssistantProvider.Draft;
import com.shsc.assistant.AssistantProvider.ProviderException;
import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.homes.HomeRepository;
import com.shsc.homes.HomeRepository.Home;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.shared.i18n.UiTexts;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;

/**
 * AI security assistant (Milestone 16, docs/25-AI-ASSISTANT.md). Read-only and stateless: it reads
 * the data of one home of the caller's tenant, asks the configured provider and shows the answer
 * only if it is grounded in that data, otherwise the deterministic LOCAL answer. Questions and
 * answers are not stored; the audit records only that a question was asked.
 */
@Service
public class AssistantService {

    private static final Logger LOG = LoggerFactory.getLogger(AssistantService.class);
    private static final Duration WINDOW = Duration.ofMinutes(1);

    public record Citation(String id, String kind, String label, String severity, String ip) {
    }

    public record Answer(String answer, List<Citation> citations, String provider, boolean fallback,
            String fallbackReason, UUID scanId, Instant dataAsOf, Instant generatedAt) {
    }

    private final HomeRepository homes;
    private final AccessPolicy access;
    private final AssistantContextLoader loader;
    private final LocalAssistantProvider local;
    private final AssistantProvider provider;
    private final AuditLog audit;
    private final TransactionTemplate tx;
    private final Clock clock;
    private final int maxPerMinute;
    private final Map<UUID, Deque<Instant>> recent = new ConcurrentHashMap<>();

    public AssistantService(HomeRepository homes, AccessPolicy access, AssistantContextLoader loader,
            LocalAssistantProvider local, List<AssistantProvider> providers, AuditLog audit, TransactionTemplate tx,
            Clock clock, @Value("${shsc.assistant.provider:LOCAL}") String providerName,
            @Value("${shsc.assistant.max-per-user-per-minute:20}") int maxPerMinute) {
        this.homes = homes;
        this.access = access;
        this.loader = loader;
        this.local = local;
        this.audit = audit;
        this.tx = tx;
        this.clock = clock;
        this.maxPerMinute = maxPerMinute;
        AssistantProvider chosen = providers.stream().filter(p -> p.name().equalsIgnoreCase(providerName.strip()))
                .findFirst().orElse(null);
        if (chosen == null || !chosen.available()) {
            LOG.warn("Assistant provider {} not available: using LOCAL", providerName);
            chosen = local;
        }
        this.provider = chosen;
        LOG.info("Assistant provider: {}", chosen.name());
    }

    public Answer ask(UUID homeId, String question, String locale, ClientInfo client) {
        String lang = UiTexts.lang(locale);
        record Loaded(AuthenticatedUser user, Home home, AssistantFacts facts) {
        }
        Loaded loaded = tx.execute(status -> {
            Home home = homes.find(homeId).orElseThrow(ApiException::notFound);
            // the answers contain findings and devices of the home
            access.requireOnHome(Permissions.DEVICE_READ, homeId);
            AuthenticatedUser user = access.requireOnHome(Permissions.FINDING_READ, homeId);
            throttle(user.userId());
            return new Loaded(user, home, loader.load(home, lang));
        });
        AssistantFacts facts = loaded.facts();

        Draft draft = null;
        String usedProvider = local.name();
        String fallbackReason = null;
        List<String> cited = null;
        if (provider != local) {
            // outside the transaction: an LLM call can take seconds
            try {
                Draft candidate = provider.answer(question, lang, facts);
                GroundingValidator.Result check = GroundingValidator.check(candidate, facts);
                if (check.grounded()) {
                    draft = candidate;
                    cited = check.citations();
                    usedProvider = provider.name();
                } else {
                    fallbackReason = "NOT_GROUNDED";
                    LOG.warn("Assistant answer of {} rejected: {}", provider.name(), check.reason());
                }
            } catch (ProviderException e) {
                fallbackReason = "PROVIDER_UNAVAILABLE";
                LOG.warn("Assistant provider {} failed: {}", provider.name(), e.getMessage());
            }
        }
        if (draft == null) {
            draft = local.answer(question, lang, facts);
            cited = draft.citations();
        }
        Map<String, Fact> byId = facts.byId();
        List<Citation> citations = cited.stream().distinct().map(byId::get).map(AssistantService::citation).toList();
        Answer answer = new Answer(draft.text(), citations, usedProvider, fallbackReason != null, fallbackReason,
                facts.scanId(), facts.dataAsOf(), clock.instant());

        String providerUsed = usedProvider;
        String reason = fallbackReason == null ? "NONE" : fallbackReason;
        tx.executeWithoutResult(status -> audit.record(AuditEvent.of(AuditAction.ASSISTANT_QUERY)
                .tenant(loaded.user().tenantId()).user(loaded.user().userId()).client(client)
                .target("HOME", homeId).detail("provider", providerUsed).detail("fallback", reason)
                .detail("questionLength", question.length()).detail("citations", citations.size()).build()));
        return answer;
    }

    private void throttle(UUID userId) {
        Instant now = clock.instant();
        Deque<Instant> times = recent.computeIfAbsent(userId, k -> new ArrayDeque<>());
        synchronized (times) {
            while (!times.isEmpty() && times.peekFirst().isBefore(now.minus(WINDOW))) {
                times.pollFirst();
            }
            if (times.size() >= maxPerMinute) {
                throw ApiException.tooManyRequests(Duration.between(now, times.peekFirst().plus(WINDOW)));
            }
            times.addLast(now);
        }
    }

    private static Citation citation(Fact f) {
        return switch (f) {
            case Finding x -> new Citation(x.id(), x.kind(), x.label(), x.severity(), x.ip());
            case Device x -> new Citation(x.id(), x.kind(), x.label(), null, x.ip());
            default -> new Citation(f.id(), f.kind(), f.label(), null, null);
        };
    }
}

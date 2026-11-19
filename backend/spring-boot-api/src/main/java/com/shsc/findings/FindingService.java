package com.shsc.findings;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.alerts.AlertService;
import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.findings.FindingRepository.DeviceVulnerability;
import com.shsc.findings.FindingRepository.Evidence;
import com.shsc.findings.FindingRepository.Filter;
import com.shsc.findings.FindingRepository.Finding;
import com.shsc.findings.FindingRepository.HomeVulnerability;
import com.shsc.homes.HomeRepository;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.risk.RiskService;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;
import com.shsc.vulnintel.VulnerabilityRepository;
import com.shsc.vulnintel.VulnerabilityRepository.CveDetail;

/**
 * Findings of a home and their manual triage (docs/19-SECURITY-ANALYSIS.md §5). RESOLVED is set
 * only by a later scan that covered the finding; a user can acknowledge a finding, mark it as a
 * false positive or an accepted risk (reason mandatory, audited) or reopen it.
 */
@Service
public class FindingService {

    private static final int MAX_FINDINGS = 500;
    private static final int MAX_EVIDENCE = 20;
    private static final Set<String> STATUSES = Set.of("OPEN", "ACKNOWLEDGED", "RESOLVED", "FALSE_POSITIVE",
            "ACCEPTED_RISK");
    private static final Set<String> TRIAGE = Set.of("OPEN", "ACKNOWLEDGED", "FALSE_POSITIVE", "ACCEPTED_RISK");
    /** Statuses counted by the risk score. */
    private static final Set<String> COUNTED = Set.of("OPEN", "ACKNOWLEDGED");
    private static final Set<String> SEVERITIES = Set.of("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL");
    private static final Set<String> TYPES = Set.of("CONFIRMED_VULNERABILITY", "POTENTIAL_RISK",
            "SUSPICIOUS_CONFIGURATION", "UNVERIFIED_INFORMATION");

    public record FindingDetail(Finding finding, List<Evidence> evidence, List<DeviceVulnerability> matches,
            List<CveDetail> vulnerabilities) {
    }

    private final FindingRepository findings;
    private final VulnerabilityRepository vulnerabilities;
    private final HomeRepository homes;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final RiskService risk;
    private final AlertService alerts;
    private final Clock clock;

    public FindingService(FindingRepository findings, VulnerabilityRepository vulnerabilities, HomeRepository homes,
            AccessPolicy access, AuditLog audit, RiskService risk, AlertService alerts, Clock clock) {
        this.risk = risk;
        this.alerts = alerts;
        this.findings = findings;
        this.vulnerabilities = vulnerabilities;
        this.homes = homes;
        this.access = access;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public List<Finding> list(UUID homeId, String status, String severity, String type) {
        homes.find(homeId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.FINDING_READ, homeId);
        return findings.forHome(homeId, new Filter(value(status, STATUSES, "status"),
                value(severity, SEVERITIES, "severity"), value(type, TYPES, "type")), MAX_FINDINGS);
    }

    /** CVEs matched to the devices of the home (findings not resolved). */
    @Transactional(readOnly = true)
    public List<HomeVulnerability> vulnerabilities(UUID homeId) {
        homes.find(homeId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.FINDING_READ, homeId);
        return findings.forHomeVulnerabilities(homeId, MAX_FINDINGS);
    }

    @Transactional(readOnly = true)
    public FindingDetail detail(UUID id) {
        Finding f = findings.find(id).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.FINDING_READ, f.homeId());
        return detailOf(f);
    }

    @Transactional
    public FindingDetail changeStatus(UUID id, String status, String reason, ClientInfo client) {
        Finding f = findings.lock(id).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.FINDING_TRIAGE, f.homeId());
        String target = status == null ? null : status.trim();
        if (target == null || !TRIAGE.contains(target)) {
            throw ApiException.badRequest("INVALID_STATUS",
                    "Status must be OPEN, ACKNOWLEDGED, FALSE_POSITIVE or ACCEPTED_RISK (RESOLVED is set by a scan).");
        }
        if ("RESOLVED".equals(f.status())) {
            throw new ApiException(HttpStatus.CONFLICT, "FINDING_RESOLVED",
                    "A resolved finding reopens by itself if a later scan detects it again.");
        }
        String text = reason == null || reason.isBlank() ? null : reason.strip();
        if (text != null && text.length() > 500) {
            throw ApiException.badRequest("INVALID_REASON", "The reason is at most 500 characters.");
        }
        if (!"OPEN".equals(target) && text == null) {
            throw ApiException.badRequest("REASON_REQUIRED", "A reason is required.");
        }
        if (!target.equals(f.status()) || (text != null && !text.equals(f.statusReason()))) {
            Instant now = clock.instant();
            findings.setStatus(id, target, text, user.userId(), now);
            audit.record(AuditEvent.of(AuditAction.FINDING_STATUS_CHANGED).tenant(f.tenantId()).user(user.userId())
                    .client(client).target("FINDING", id).detail("homeId", f.homeId()).detail("rule", f.ruleId())
                    .detail("old", f.status()).detail("new", target).build());
            if (COUNTED.contains(f.status()) != COUNTED.contains(target)) {
                // the finding starts or stops counting in the score (M11)
                risk.recomputeAfterTriage(f.homeId(), now);
            }
            alerts.onFindingTriaged(id, target, now); // a dismissed finding no longer needs its alert (M13)
        }
        return detailOf(findings.find(id).orElseThrow());
    }

    private FindingDetail detailOf(Finding f) {
        List<DeviceVulnerability> matches = findings.vulnerabilities(f.id());
        List<String> ids = matches.stream().map(DeviceVulnerability::cveId).distinct().limit(50).toList();
        return new FindingDetail(f, findings.evidence(f.id(), MAX_EVIDENCE), matches, vulnerabilities.details(ids));
    }

    private static String value(String raw, Set<String> allowed, String field) {
        if (raw == null || raw.isBlank()) {
            return null;
        }
        String v = raw.trim();
        if (!allowed.contains(v)) {
            throw ApiException.badRequest("INVALID_FILTER", "Unknown " + field + ".");
        }
        return v;
    }
}

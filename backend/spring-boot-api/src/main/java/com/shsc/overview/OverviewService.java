package com.shsc.overview;

import java.math.BigDecimal;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.homes.HomeRepository.Home;
import com.shsc.homes.HomeService;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.overview.OverviewRepository.FindingFigures;
import com.shsc.overview.OverviewRepository.RiskFigures;

/**
 * Dashboard overview (Milestone 12): every home the user can read with its security figures.
 * The security part of a home (score, findings, devices, last scan) is returned only when the
 * user holds {@code finding:read} on that home, the permission of the risk page (ADR-059);
 * otherwise it is null and the home is listed by name only.
 */
@Service
public class OverviewService {

    public record HomeOverview(UUID homeId, String name, UUID customerId, Security security) {
    }

    public record Security(Integer score, String riskLevel, String rating, boolean provisional, BigDecimal coverage,
            Integer scoreChange, Instant computedAt, String notComputedReason, Map<String, Integer> openFindings,
            int kevFindings, int devices, Instant lastScanAt) {
    }

    private final HomeService homes;
    private final OverviewRepository repository;
    private final AccessPolicy access;

    public OverviewService(HomeService homes, OverviewRepository repository, AccessPolicy access) {
        this.homes = homes;
        this.repository = repository;
        this.access = access;
    }

    @Transactional(readOnly = true)
    public List<HomeOverview> overview() {
        List<Home> visible = homes.list(null); // requires home:read, applies the user's scopes
        AuthenticatedUser user = access.currentUser();
        List<UUID> readable = visible.stream()
                .map(Home::id)
                .filter(id -> access.hasOnHome(user, Permissions.FINDING_READ, id))
                .toList();
        Map<UUID, RiskFigures> risk = repository.risk(readable);
        Map<UUID, FindingFigures> findings = repository.findings(readable);
        Map<UUID, Integer> devices = repository.deviceCounts(readable);
        Map<UUID, Instant> scans = repository.lastCompletedScans(readable);
        List<HomeOverview> out = new ArrayList<>(visible.size());
        for (Home home : visible) {
            Security security = null;
            if (readable.contains(home.id())) {
                RiskFigures r = risk.get(home.id());
                FindingFigures f = findings.get(home.id());
                // after a DISCOVERY scan the current snapshot has no score: report why, keep the last score
                String notComputed = r == null ? null : r.currentNotComputedReason();
                security = new Security(r == null ? null : r.score(), r == null ? null : r.riskLevel(),
                        r == null ? null : r.rating(), r != null && r.provisional(), r == null ? null : r.coverage(),
                        r == null ? null : r.scoreChange(), r == null ? null : r.computedAt(), notComputed,
                        f.bySeverity(), f.kev(), devices.getOrDefault(home.id(), 0), scans.get(home.id()));
            }
            out.add(new HomeOverview(home.id(), home.name(), home.customerId(), security));
        }
        return out;
    }
}

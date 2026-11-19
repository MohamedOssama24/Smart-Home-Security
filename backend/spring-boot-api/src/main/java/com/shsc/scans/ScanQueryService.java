package com.shsc.scans;

import java.util.List;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.homes.HomeRepository;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.Permissions;
import com.shsc.integrations.HomeAssistantRepository;
import com.shsc.scans.ScanRepository.Observation;
import com.shsc.scans.ScanRepository.Scan;
import com.shsc.scans.ScanRepository.ScanEvent;
import com.shsc.scans.ScanRepository.Target;
import com.shsc.shared.web.ApiException;

/** Read side of the scans for users ({@code scan:read} on the home; other tenants: 404). */
@Service
public class ScanQueryService {

    static final int HISTORY_LIMIT = 20;

    public record ScanDetail(Scan scan, List<Target> targets, List<ScanEvent> events) {
    }

    private final ScanRepository scans;
    private final PortRepository ports;
    private final HomeRepository homes;
    private final AccessPolicy access;
    private final HomeAssistantRepository homeAssistant;

    public ScanQueryService(ScanRepository scans, PortRepository ports, HomeRepository homes, AccessPolicy access,
            HomeAssistantRepository homeAssistant) {
        this.scans = scans;
        this.ports = ports;
        this.homeAssistant = homeAssistant;
        this.homes = homes;
        this.access = access;
    }

    @Transactional(readOnly = true)
    public List<Scan> history(UUID homeId) {
        homes.find(homeId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.SCAN_READ, homeId);
        return scans.forHome(homeId, HISTORY_LIMIT);
    }

    @Transactional(readOnly = true)
    public ScanDetail detail(UUID scanId) {
        Scan scan = readable(scanId);
        return new ScanDetail(scan, scans.targets(scanId), scans.events(scanId));
    }

    @Transactional(readOnly = true)
    public List<Observation> observations(UUID scanId) {
        readable(scanId);
        return scans.observations(scanId);
    }

    @Transactional(readOnly = true)
    public List<PortRepository.StoredPort> ports(UUID scanId) {
        readable(scanId);
        return ports.ofScan(scanId);
    }

    /** Inventory of the Home Assistant configured on the agent, if the scan has one (docs/24). */
    @Transactional(readOnly = true)
    public Optional<HomeAssistantRepository.Stored> homeAssistant(UUID scanId) {
        readable(scanId);
        return homeAssistant.ofScan(scanId);
    }

    private Scan readable(UUID scanId) {
        Scan scan = scans.find(scanId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.SCAN_READ, scan.homeId());
        return scan;
    }
}

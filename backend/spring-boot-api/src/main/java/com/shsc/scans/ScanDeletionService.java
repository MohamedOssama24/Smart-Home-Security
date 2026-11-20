package com.shsc.scans;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.devices.DeviceFingerprinter;
import com.shsc.devices.DeviceRepository;
import com.shsc.homes.HomeRepository;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.scans.ScanRepository.Scan;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;

/**
 * Deletion of scans (ADR-082), permission {@code scan:delete}, only for finished scans.
 * <ul>
 * <li>One scan: its results, reports and risk snapshot are deleted. Devices and findings seen
 * only by that scan are deleted; the others point to their previous/next scan and the devices
 * whose last scan was deleted are computed again from the observations of their new last scan.</li>
 * <li>Inventory of a home: all its scans, devices, findings, people, reports, risk history and
 * alerts. The home, its networks and its agent stay.</li>
 * </ul>
 * Both are irreversible (no backup) and audited with the counts, never with the content.
 */
@Service
public class ScanDeletionService {

    public record Deleted(int scans, int devices, int findings) {
    }

    private final ScanRepository scans;
    private final DeviceRepository devices;
    private final DeviceFingerprinter fingerprinter;
    private final HomeRepository homes;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final Clock clock;
    private final JdbcClient jdbc;

    public ScanDeletionService(ScanRepository scans, DeviceRepository devices, DeviceFingerprinter fingerprinter,
            HomeRepository homes, AccessPolicy access, AuditLog audit, Clock clock, JdbcClient jdbc) {
        this.scans = scans;
        this.devices = devices;
        this.fingerprinter = fingerprinter;
        this.homes = homes;
        this.access = access;
        this.audit = audit;
        this.clock = clock;
        this.jdbc = jdbc;
    }

    @Transactional
    public Deleted deleteScan(UUID scanId, ClientInfo client) {
        Scan scan = scans.lock(scanId).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.SCAN_DELETE, scan.homeId());
        if (!scan.status().terminal()) {
            throw new ApiException(HttpStatus.CONFLICT, "SCAN_ACTIVE", "The scan is still running: cancel it first.",
                    Map.of("status", scan.status().name()));
        }
        // devices seen only by this scan
        List<UUID> only = ids("""
                SELECT d.id FROM devices d
                WHERE d.home_id = :home AND (d.first_scan_id = :scan OR d.last_scan_id = :scan)
                  AND NOT EXISTS (SELECT 1 FROM scan_observations o WHERE o.device_id = d.id AND o.scan_id <> :scan)
                FOR UPDATE OF d""", scan);
        if (!only.isEmpty()) {
            jdbc.sql("DELETE FROM devices WHERE id IN (:ids)").param("ids", only).update();
        }
        List<UUID> lastChanged = ids("SELECT id FROM devices WHERE home_id = :home AND last_scan_id = :scan FOR UPDATE",
                scan);
        jdbc.sql("""
                UPDATE devices d SET
                    last_scan_id = (SELECT o.scan_id FROM scan_observations o JOIN scans s ON s.id = o.scan_id
                                    WHERE o.device_id = d.id AND o.scan_id <> :scan
                                    ORDER BY s.requested_at DESC LIMIT 1),
                    version = d.version + 1
                WHERE d.home_id = :home AND d.last_scan_id = :scan""")
                .param("home", scan.homeId()).param("scan", scanId).update();
        jdbc.sql("""
                UPDATE devices d SET last_seen_at = (SELECT max(o.observed_at) FROM scan_observations o
                                                     WHERE o.device_id = d.id AND o.scan_id = d.last_scan_id)
                WHERE d.id IN (:ids)""")
                .param("ids", lastChanged.isEmpty() ? List.of(new UUID(0, 0)) : lastChanged).update();
        jdbc.sql("""
                UPDATE devices d SET
                    first_scan_id = x.scan_id, first_seen_at = LEAST(d.last_seen_at, x.seen)
                FROM (SELECT DISTINCT ON (o.device_id) o.device_id, o.scan_id,
                          min(o.observed_at) OVER (PARTITION BY o.device_id, o.scan_id) AS seen
                      FROM scan_observations o JOIN scans s ON s.id = o.scan_id
                      WHERE o.scan_id <> :scan
                        AND o.device_id IN (SELECT id FROM devices WHERE home_id = :home AND first_scan_id = :scan)
                      ORDER BY o.device_id, s.requested_at) x
                WHERE d.id = x.device_id""")
                .param("home", scan.homeId()).param("scan", scanId).update();
        // findings: deleted when only this scan found them, otherwise they point to another scan
        int findings = jdbc.sql("""
                DELETE FROM findings f
                WHERE f.home_id = :home AND (f.first_scan_id = :scan OR f.last_scan_id = :scan)
                  AND NOT EXISTS (SELECT 1 FROM finding_evidence e WHERE e.finding_id = f.id AND e.scan_id <> :scan)""")
                .param("home", scan.homeId()).param("scan", scanId).update();
        for (String column : List.of("last_scan_id", "first_scan_id")) {
            String order = column.startsWith("last") ? "DESC" : "ASC";
            jdbc.sql("UPDATE findings f SET " + column + " = (SELECT e.scan_id FROM finding_evidence e "
                    + "JOIN scans s ON s.id = e.scan_id WHERE e.finding_id = f.id AND e.scan_id <> :scan "
                    + "ORDER BY s.requested_at " + order + " LIMIT 1) "
                    + "WHERE f.home_id = :home AND f." + column + " = :scan")
                    .param("home", scan.homeId()).param("scan", scanId).update();
        }
        jdbc.sql("DELETE FROM reports WHERE scan_id = :scan").param("scan", scanId).update();
        jdbc.sql("DELETE FROM risk_snapshots WHERE scan_id = :scan").param("scan", scanId).update();
        jdbc.sql("DELETE FROM scans WHERE id = :scan").param("scan", scanId).update();
        Instant now = clock.instant();
        for (UUID id : lastChanged) {
            devices.find(id).ifPresent(d -> fingerprinter.reclassify(d, now));
        }
        Deleted result = new Deleted(1, only.size(), findings);
        audit.record(AuditEvent.of(AuditAction.SCAN_DELETED).tenant(user.tenantId()).user(user.userId())
                .client(client).target("SCAN", scanId).detail("homeId", scan.homeId())
                .detail("devicesDeleted", result.devices()).detail("findingsDeleted", findings).build());
        return result;
    }

    @Transactional
    public Deleted clearHome(UUID homeId, ClientInfo client) {
        homes.find(homeId).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.SCAN_DELETE, homeId);
        if (scans.activeOfHome(homeId).isPresent()) {
            throw ApiException.conflict("SCAN_ACTIVE", "A scan of this home is running: cancel it first.");
        }
        jdbc.sql("DELETE FROM home_people WHERE home_id = :home").param("home", homeId).update();
        jdbc.sql("DELETE FROM alerts WHERE home_id = :home").param("home", homeId).update();
        int findings = jdbc.sql("DELETE FROM findings WHERE home_id = :home").param("home", homeId).update();
        int deviceCount = jdbc.sql("DELETE FROM devices WHERE home_id = :home").param("home", homeId).update();
        jdbc.sql("DELETE FROM reports WHERE home_id = :home").param("home", homeId).update();
        jdbc.sql("DELETE FROM risk_snapshots WHERE home_id = :home").param("home", homeId).update();
        int scanCount = jdbc.sql("DELETE FROM scans WHERE home_id = :home").param("home", homeId).update();
        Deleted result = new Deleted(scanCount, deviceCount, findings);
        audit.record(AuditEvent.of(AuditAction.HOME_INVENTORY_CLEARED).tenant(user.tenantId()).user(user.userId())
                .client(client).target("HOME", homeId).detail("scansDeleted", scanCount)
                .detail("devicesDeleted", deviceCount).detail("findingsDeleted", findings).build());
        return result;
    }

    private List<UUID> ids(String sql, Scan scan) {
        return jdbc.sql(sql).param("home", scan.homeId()).param("scan", scan.id()).query(UUID.class).list();
    }
}

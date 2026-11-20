package com.shsc.scans;

import java.util.UUID;

import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.scans.ScanDeletionService.Deleted;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;

/** Irreversible deletion of a finished scan, or of all the scans and the inventory of a home (ADR-082). */
@RestController
public class ScanDeletionController {

    private final ScanDeletionService service;

    public ScanDeletionController(ScanDeletionService service) {
        this.service = service;
    }

    @DeleteMapping("/api/v1/scans/{scanId}")
    public Deleted deleteScan(@PathVariable UUID scanId, HttpServletRequest http) {
        return service.deleteScan(scanId, ClientInfo.from(http));
    }

    @DeleteMapping("/api/v1/homes/{homeId}/inventory")
    public Deleted clearHome(@PathVariable UUID homeId, HttpServletRequest http) {
        return service.clearHome(homeId, ClientInfo.from(http));
    }
}

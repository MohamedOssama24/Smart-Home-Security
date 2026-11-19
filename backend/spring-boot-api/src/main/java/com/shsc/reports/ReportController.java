package com.shsc.reports;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;
import java.util.UUID;

import org.springframework.http.CacheControl;
import org.springframework.http.ContentDisposition;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.reports.ReportRepository.Report;
import com.shsc.reports.ReportService.Download;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.Size;

/** PDF security reports (docs/05-API.md §Reports). */
@RestController
public class ReportController {

    public record ReportRequest(@Size(max = 5) String locale) {
    }

    public record ReportResponse(UUID id, UUID homeId, UUID scanId, String locale, String status, String errorCode,
            Integer sizeBytes, Integer pages, String sha256, Instant requestedAt, Instant generatedAt) {
    }

    private static final DateTimeFormatter FILE_DATE = DateTimeFormatter.ofPattern("yyyy-MM-dd")
            .withZone(ZoneOffset.UTC);

    private final ReportService service;

    public ReportController(ReportService service) {
        this.service = service;
    }

    @PostMapping("/api/v1/scans/{scanId}/reports")
    public ResponseEntity<ReportResponse> request(@PathVariable UUID scanId,
            @RequestBody(required = false) ReportRequest request, HttpServletRequest http) {
        Report r = service.request(scanId, request == null ? null : request.locale(), ClientInfo.from(http));
        return ResponseEntity.status(HttpStatus.ACCEPTED).body(response(r));
    }

    @GetMapping("/api/v1/reports/{id}")
    public ReportResponse get(@PathVariable UUID id) {
        return response(service.get(id));
    }

    @GetMapping("/api/v1/homes/{homeId}/reports")
    public List<ReportResponse> list(@PathVariable UUID homeId) {
        return service.list(homeId).stream().map(ReportController::response).toList();
    }

    @GetMapping("/api/v1/reports/{id}/download")
    public ResponseEntity<byte[]> download(@PathVariable UUID id, HttpServletRequest http) {
        Download d = service.download(id, ClientInfo.from(http));
        String name = "security-report-" + FILE_DATE.format(d.report().generatedAt()) + "-" + d.report().locale()
                + ".pdf";
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_PDF)
                .header(HttpHeaders.CONTENT_DISPOSITION, ContentDisposition.attachment().filename(name).build()
                        .toString())
                .cacheControl(CacheControl.noStore())
                .body(d.pdf());
    }

    private static ReportResponse response(Report r) {
        return new ReportResponse(r.id(), r.homeId(), r.scanId(), r.locale(), r.status(), r.errorCode(), r.sizeBytes(),
                r.pages(), r.sha256(), r.requestedAt(), r.generatedAt());
    }
}

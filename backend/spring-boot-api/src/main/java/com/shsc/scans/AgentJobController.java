package com.shsc.scans;

import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.people.PeopleRepository.ScanIdentity;
import com.shsc.agents.auth.AgentPrincipal;
import com.shsc.integrations.HomeAssistantRepository.GatewayDevice;
import com.shsc.integrations.HomeAssistantRepository.Inventory;
import com.shsc.shared.web.ApiException;
import com.shsc.devices.images.ImageFormat;
import com.shsc.devices.images.DeviceImageRepository.ScanIcon;
import com.shsc.scans.AgentJobService.BatchAck;
import com.shsc.scans.AgentJobService.CompleteAck;
import com.shsc.scans.AgentJobService.Lease;
import com.shsc.scans.AgentJobService.Outcome;
import com.shsc.scans.AgentJobService.ProgressAck;
import com.shsc.scans.AgentJobService.SignedJob;
import com.shsc.scans.PortRepository.Port;
import com.shsc.scans.PortRepository.Service;
import com.shsc.scans.ScanRepository.Observation;

import jakarta.validation.Valid;
import jakarta.validation.constraints.Max;
import jakarta.validation.constraints.Min;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Size;
import tools.jackson.databind.json.JsonMapper;

/** Scan jobs for agents (agent access token only): long polling, ack, progress, results, complete. */
@RestController
@RequestMapping("/api/v1/agent")
public class AgentJobController {

    static final int SCHEMA_MIN = 1;
    static final int SCHEMA_MAX = 1;

    public record ProgressRequest(
            @NotNull @Pattern(regexp = "PREPARING|INTERFACES|DISCOVERY|PORTS|UPLOADING") String phase,
            @NotNull @Min(0) @Max(100) Integer percent,
            @NotNull @Min(0) @Max(100_000) Integer devicesDiscovered) {
    }

    public record ObservationItem(
            @NotNull @Size(min = 2, max = 45) @Pattern(regexp = "[0-9a-fA-F.:]+") String ip,
            @Pattern(regexp = "[0-9a-f]{2}(:[0-9a-f]{2}){5}") String mac,
            @NotNull @Pattern(regexp = METHODS) String method,
            @Size(max = 64) String iface,
            @Pattern(regexp = "[^\\p{Cntrl}]{1,255}") String hostname,
            Map<String, Object> details,
            @NotNull Instant observedAt) {
    }

    /**
     * Discovery methods of the agent (docs/16-NETWORK-DISCOVERY.md); PORTSCAN carries the port
     * counters of one host (docs/18-PORT-SCANNING.md).
     */
    static final String METHODS = "ARP|SELF|ICMP|MDNS|SSDP|UPNP_IGD|NETBIOS|RDNS|NDP|TR064|SNMP|PORTSCAN";
    /** Serialized size limit of the details of one observation (the column allows 4096). */
    static final int MAX_DETAILS_BYTES = 3500;

    /** Service identified by the agent on a port (docs/18 §3). */
    public record ServiceItem(
            @NotNull @Pattern(regexp = "[a-z0-9-]{1,32}") String name,
            @Pattern(regexp = "[^\\p{Cntrl}]{1,128}") String product,
            @Pattern(regexp = "[^\\p{Cntrl}]{1,64}") String version,
            @NotNull @Pattern(regexp = "PROBABLE|CONFIRMED") String status,
            @NotNull @Pattern(regexp = "HIGH|MEDIUM|LOW") String confidence,
            Map<String, Object> evidence,
            Map<String, Object> tls) {
    }

    /** A port of a host; the agent only uploads the OPEN ones (the others are counted). */
    public record PortItem(
            @NotNull @Size(min = 2, max = 45) @Pattern(regexp = "[0-9a-fA-F.:]+") String ip,
            @NotNull @Pattern(regexp = "TCP|UDP") String protocol,
            @NotNull @Min(1) @Max(65535) Integer port,
            @NotNull @Pattern(regexp = "OPEN|CLOSED|FILTERED|OPEN_FILTERED|UNKNOWN") String state,
            @Pattern(regexp = "[a-z-]{1,40}") String reason,
            @Valid ServiceItem service,
            @NotNull Instant observedAt) {
    }

    /** Text read from Home Assistant: printable, no control characters. */
    static final String TEXT = "[^\\p{Cntrl}]+";

    /** A device known to Home Assistant (docs/24 §3). */
    public record GatewayDeviceItem(
            @Size(max = 255) @Pattern(regexp = TEXT) String name,
            @Size(max = 128) @Pattern(regexp = TEXT) String manufacturer,
            @Size(max = 128) @Pattern(regexp = TEXT) String model,
            @Size(max = 64) @Pattern(regexp = TEXT) String swVersion,
            @NotNull @Pattern(regexp = "ZIGBEE|ZWAVE|MATTER|THREAD|BLUETOOTH|IP|OTHER") String protocol,
            @Size(max = 8) List<@NotNull @Pattern(regexp = "[0-9a-f]{2}(:[0-9a-f]{2}){5}") String> macs,
            @NotNull @Min(0) @Max(10_000) Integer entities) {
    }

    /** Read-only inventory of the Home Assistant configured by the owner on the agent. */
    public record HomeAssistantItem(
            @NotNull @Size(min = 2, max = 45) @Pattern(regexp = "[0-9a-fA-F.:]+") String ip,
            @Pattern(regexp = "[0-9A-Za-z.+-]{1,40}") String version,
            @NotNull Boolean https,
            @NotNull @Size(max = 500) List<@NotNull @Valid GatewayDeviceItem> devices,
            Boolean truncated,
            @NotNull Instant observedAt) {
    }

    public record ResultsRequest(
            @NotNull @Min(SCHEMA_MIN) @Max(SCHEMA_MAX) Integer schemaVersion,
            @NotNull @Min(0) @Max(9999) Integer batchSeq,
            @NotNull @Size(max = 500) List<@NotNull @Valid ObservationItem> observations,
            @Size(max = 500) List<@NotNull @Valid PortItem> ports,
            @Valid HomeAssistantItem homeAssistant,
            @Size(max = 16) List<@NotNull @Valid IconItem> icons,
            @Size(max = 500) List<@NotNull @Valid IdentityItem> identities) {
    }

    /**
     * Account seen on an address of the home (M24, ADR-083): DIRECTORY from the Active Directory
     * logons, FIREWALL from the Sophos authentications read by the agent.
     */
    public record IdentityItem(
            @NotNull @Size(min = 2, max = 45) @Pattern(regexp = "[0-9a-fA-F.:]+") String ip,
            @NotNull @Size(min = 1, max = 100) @Pattern(regexp = "[^\\p{Cntrl}\\\\@]+") String account,
            @NotNull @Pattern(regexp = "DIRECTORY|FIREWALL") String source,
            @NotNull Instant observedAt) {
    }

    /** Icon a device declares about itself (M23, ADR-077); data: base64 of a PNG or JPEG of at most 32 KB. */
    public record IconItem(
            @NotNull @Size(min = 2, max = 45) @Pattern(regexp = "[0-9a-fA-F.:]+") String ip,
            @NotNull @Pattern(regexp = "UPNP") String origin,
            @NotNull @Pattern(regexp = "image/png|image/jpeg") String contentType,
            @Min(1) @Max(1024) Integer width,
            @Min(1) @Max(1024) Integer height,
            @NotNull @Size(min = 1, max = MAX_ICON_BYTES) byte[] data,
            @NotNull Instant observedAt) {
    }

    static final int MAX_ICON_BYTES = 32 * 1024;

    public record CompleteRequest(
            @NotNull @Min(SCHEMA_MIN) @Max(SCHEMA_MAX) Integer schemaVersion,
            @NotNull @Min(0) @Max(10_000) Integer totalBatches,
            @NotNull Outcome outcome,
            @NotNull @Size(max = 20) List<@NotNull @Pattern(regexp = "[A-Z_]{1,40}") String> warnings,
            @Pattern(regexp = "[A-Z_]{1,40}") String errorCode) {
    }

    private final AgentJobService jobs;
    private final JsonMapper json;

    public AgentJobController(AgentJobService jobs, JsonMapper json) {
        this.jobs = jobs;
        this.json = json;
    }

    /** 200 with a signed job, or 204 when nothing arrived within {@code wait} seconds (max 25). */
    @GetMapping("/jobs/next")
    public ResponseEntity<SignedJob> next(@AuthenticationPrincipal AgentPrincipal agent,
            @RequestParam(defaultValue = "25") @Min(0) @Max(60) int wait) throws InterruptedException {
        return jobs.nextJob(agent, Duration.ofSeconds(Math.max(0, Math.min(wait, 60))))
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.noContent().build());
    }

    @PostMapping("/scans/{scanId}/ack")
    public Lease ack(@AuthenticationPrincipal AgentPrincipal agent, @PathVariable UUID scanId) {
        return jobs.ack(agent, scanId);
    }

    @PostMapping("/scans/{scanId}/progress")
    public ProgressAck progress(@AuthenticationPrincipal AgentPrincipal agent, @PathVariable UUID scanId,
            @Valid @RequestBody ProgressRequest request) {
        return jobs.progress(agent, scanId, request.phase(), request.percent(), request.devicesDiscovered());
    }

    @PostMapping("/scans/{scanId}/results")
    public BatchAck results(@AuthenticationPrincipal AgentPrincipal agent, @PathVariable UUID scanId,
            @Valid @RequestBody ResultsRequest request) {
        List<Observation> observations = request.observations().stream()
                .map(o -> new Observation(o.ip(), o.mac(), o.method(), o.iface(), o.hostname(), details(o),
                        o.observedAt()))
                .toList();
        List<Port> ports = request.ports() == null ? List.of() : request.ports().stream()
                .map(p -> new Port(p.ip(), p.protocol(), p.port(), p.state(), p.reason(), p.observedAt(),
                        service(p.service())))
                .toList();
        HomeAssistantItem ha = request.homeAssistant();
        Inventory inventory = ha == null ? null : new Inventory(ha.ip(), ha.version(), ha.https(), ha.observedAt(),
                ha.devices().stream().map(d -> new GatewayDevice(blank(d.name()), blank(d.manufacturer()),
                        blank(d.model()), blank(d.swVersion()), d.protocol(),
                        d.macs() == null ? List.of() : d.macs().stream().distinct().toList(), d.entities()))
                        .toList(),
                Boolean.TRUE.equals(ha.truncated()));
        // the hash covers everything stored; batches without ports keep the M6-M8 hash
        String raw;
        if (ha != null) {
            raw = json.writeValueAsString(Map.of("observations", request.observations(), "homeAssistant", ha));
        } else {
            raw = ports.isEmpty() ? json.writeValueAsString(request.observations())
                    : json.writeValueAsString(Map.of("observations", request.observations(), "ports", request.ports()));
        }
        if (ha != null && !ports.isEmpty()) {
            throw ApiException.badRequest("INVALID_BATCH", "The Home Assistant inventory travels in its own batch.");
        }
        // M23: icons travel in their own batches; each one must really be a small PNG or JPEG
        List<ScanIcon> icons = new java.util.ArrayList<>();
        if (request.icons() != null && !request.icons().isEmpty()) {
            if (ha != null || !ports.isEmpty() || !observations.isEmpty()) {
                throw ApiException.badRequest("INVALID_BATCH", "Device icons travel in their own batch.");
            }
            for (IconItem i : request.icons()) {
                ImageFormat.Info info = ImageFormat.inspect(i.data(), MAX_ICON_BYTES, 1024)
                        .filter(f -> f.contentType().equals(i.contentType()))
                        .orElseThrow(() -> ApiException.badRequest("INVALID_ICON",
                                "A device icon is not a PNG or JPEG of at most 32 KB and 1024 pixels."));
                icons.add(new ScanIcon(i.ip(), i.origin(), info, i.data(), i.observedAt()));
            }
            raw = json.writeValueAsString(Map.of("observations", request.observations(), "icons", request.icons()));
        }
        // M24: identities travel in their own batches
        List<ScanIdentity> identities = new java.util.ArrayList<>();
        if (request.identities() != null && !request.identities().isEmpty()) {
            if (ha != null || !ports.isEmpty() || !observations.isEmpty() || !icons.isEmpty()) {
                throw ApiException.badRequest("INVALID_BATCH", "The identities travel in their own batch.");
            }
            for (IdentityItem i : request.identities()) {
                if (i.account().isBlank()) {
                    throw ApiException.badRequest("INVALID_IDENTITY", "An identity has no account.");
                }
                identities.add(new ScanIdentity(i.ip(), i.account().strip(), i.source(), i.observedAt()));
            }
            raw = json.writeValueAsString(Map.of("observations", request.observations(),
                    "identities", request.identities()));
        }
        return jobs.results(agent, scanId, request.batchSeq(), observations, ports, inventory, icons, identities, raw);
    }

    private static String blank(String s) {
        return s == null || s.isBlank() ? null : s.strip();
    }

    private Service service(ServiceItem s) {
        if (s == null) {
            return null;
        }
        return new Service(s.name(), s.product(), s.version(), s.status(), s.confidence(),
                object(s.evidence(), "evidence"), object(s.tls(), "TLS data"));
    }

    /** A JSON object within the size limit, or 400 (null when absent or empty). */
    private String object(Map<String, Object> value, String what) {
        if (value == null || value.isEmpty()) {
            return null;
        }
        String text = json.writeValueAsString(value);
        if (text.getBytes(StandardCharsets.UTF_8).length > MAX_DETAILS_BYTES) {
            throw ApiException.badRequest("DETAILS_TOO_LARGE",
                    "The " + what + " of a service must not exceed " + MAX_DETAILS_BYTES + " bytes.");
        }
        return text;
    }

    /** Details as a JSON object, or 400 when larger than the limit (null when absent or empty). */
    private String details(ObservationItem o) {
        if (o.details() == null || o.details().isEmpty()) {
            return null;
        }
        String value = json.writeValueAsString(o.details());
        if (value.getBytes(StandardCharsets.UTF_8).length > MAX_DETAILS_BYTES) {
            throw ApiException.badRequest("DETAILS_TOO_LARGE",
                    "The details of an observation must not exceed " + MAX_DETAILS_BYTES + " bytes.");
        }
        return value;
    }

    @PostMapping("/scans/{scanId}/complete")
    public CompleteAck complete(@AuthenticationPrincipal AgentPrincipal agent, @PathVariable UUID scanId,
            @Valid @RequestBody CompleteRequest request) {
        return jobs.complete(agent, scanId, request.totalBatches(), request.outcome(), request.warnings(),
                request.errorCode());
    }
}

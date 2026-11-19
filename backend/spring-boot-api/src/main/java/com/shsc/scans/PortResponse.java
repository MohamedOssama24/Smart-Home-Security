package com.shsc.scans;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import com.shsc.scans.PortRepository.StoredPort;

import tools.jackson.core.type.TypeReference;
import tools.jackson.databind.json.JsonMapper;

/**
 * An open port and its service as shown by the API. A PROBABLE service is a guess (port
 * number or weak evidence); only a CONFIRMED one answered its protocol. Product and version
 * are what the device declared: they are never verified.
 */
public record PortResponse(UUID deviceId, String ip, String protocol, int port, String state, String reason,
        Instant observedAt, ServiceResponse service) {

    public record ServiceResponse(String name, String product, String version, String status, String confidence,
            Map<String, Object> evidence, Map<String, Object> tls) {
    }

    private static final TypeReference<Map<String, Object>> OBJECT = new TypeReference<>() {
    };

    public static PortResponse of(StoredPort p, JsonMapper json) {
        PortRepository.Service s = p.service();
        ServiceResponse service = s == null ? null : new ServiceResponse(s.name(), s.product(), s.version(),
                s.status(), s.confidence(), s.evidenceJson() == null ? Map.of() : json.readValue(s.evidenceJson(), OBJECT),
                s.tlsJson() == null ? null : json.readValue(s.tlsJson(), OBJECT));
        return new PortResponse(p.deviceId(), p.ip(), p.protocol(), p.port(), p.state(), p.reason(), p.observedAt(),
                service);
    }
}

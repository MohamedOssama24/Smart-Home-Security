package com.shsc.scans;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import com.shsc.integrations.HomeAssistantRepository;

/** {@code GET /api/v1/scans/{id}/integrations} (docs/24-INTEGRATIONS.md). */
public record IntegrationsResponse(HomeAssistant homeAssistant) {

    /**
     * Home Assistant seen by a scan. {@code https=false}: the long-lived token travelled
     * unencrypted on the LAN. {@code matchedIp}: host of the same scan with one of the MAC
     * addresses of the device.
     */
    public record HomeAssistant(String ip, String version, boolean https, int deviceCount, boolean truncated,
            Instant observedAt, Map<String, Integer> protocols, List<GatewayDevice> devices) {

        static HomeAssistant of(HomeAssistantRepository.Stored s) {
            Map<String, Integer> protocols = new TreeMap<>();
            s.devices().forEach(d -> protocols.merge(d.device().protocol(), 1, Integer::sum));
            return new HomeAssistant(s.ip(), s.version(), s.https(), s.deviceCount(), s.truncated(), s.observedAt(),
                    protocols, s.devices().stream()
                            .map(d -> new GatewayDevice(d.device().name(), d.device().manufacturer(),
                                    d.device().model(), d.device().swVersion(), d.device().protocol(),
                                    d.device().macs(), d.device().entityCount(), d.matchedIp()))
                            .toList());
        }
    }

    public record GatewayDevice(String name, String manufacturer, String model, String swVersion, String protocol,
            List<String> macs, int entities, String matchedIp) {
    }
}

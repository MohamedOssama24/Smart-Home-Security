package com.shsc.findings;

import static org.assertj.core.api.Assertions.assertThat;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.shsc.findings.FindingRule.Detection;
import com.shsc.findings.FindingRule.DeviceView;
import com.shsc.findings.FindingRule.Mapping;
import com.shsc.findings.FindingRule.PortView;
import com.shsc.findings.FindingRule.Severity;
import com.shsc.findings.FindingRule.Type;

import tools.jackson.databind.json.JsonMapper;

/**
 * The finding rules (docs/19 §4) on [MOCK] device views: positive cases and the negative cases
 * that must not raise a finding (TLS, redirect to HTTPS, router resolver, manual category).
 */
class FindingRulesTest {

    private static final JsonMapper JSON = JsonMapper.builder().build();

    private static DeviceView device(String category, List<PortView> ports) {
        return new DeviceView(UUID.randomUUID(), category, false, ports, Map.of(), List.of(), false);
    }

    private static PortView port(String protocol, int port, String service, Map<String, Object> evidence,
            Map<String, Object> tls) {
        return new PortView(protocol, port, service, null, null, "CONFIRMED", evidence, tls);
    }

    private static List<Detection> run(DeviceView d) {
        return FindingRules.all().stream().flatMap(r -> r.evaluate(d).stream()).toList();
    }

    private static List<String> ids(DeviceView d) {
        return run(d).stream().map(Detection::ruleId).toList();
    }

    @Test
    void rulesHaveUniqueIdsAndVersions() {
        Set<String> ids = new HashSet<>();
        FindingRules.all().forEach(r -> {
            assertThat(ids.add(r.id())).as(r.id()).isTrue();
            assertThat(r.id()).matches("[a-z0-9]+\\.[a-z0-9-]+");
            assertThat(r.version()).isPositive();
        });
        assertThat(ids).hasSize(14);
    }

    @Test
    void cleartextServicesAreReported() {
        List<Detection> found = run(device("NAS", List.of(
                port("TCP", 23, "telnet", null, null),
                port("TCP", 21, "ftp", null, null),
                port("TCP", 1883, "mqtt", null, null),
                port("UDP", 161, "snmp", null, null),
                port("TCP", 554, "rtsp", Map.of("status", 401, "authRequired", true), null),
                port("TCP", 7547, null, null, null))));
        assertThat(found).extracting(Detection::ruleId).containsExactlyInAnyOrder("telnet.open", "ftp.cleartext",
                "mqtt.cleartext", "snmp.enabled", "rtsp.open", "tr069.exposed");
        Detection telnet = found.stream().filter(d -> d.ruleId().equals("telnet.open")).findFirst().orElseThrow();
        assertThat(telnet.severity()).isEqualTo(Severity.HIGH);
        assertThat(telnet.type()).isEqualTo(Type.SUSPICIOUS_CONFIGURATION);
        assertThat(telnet.titleKey()).isEqualTo("findings.rule.telnet-open.title");
        // MQTT over TLS and FTP with TLS: nothing
        assertThat(ids(device("NAS", List.of(port("TCP", 8883, "mqtt", null, Map.of("versions", List.of("TLS1.3"))),
                port("TCP", 21, "ftp", null, Map.of("versions", List.of("TLS1.2"))))))).isEmpty();
    }

    @Test
    void httpLoginOnlyWithoutTlsAndWithoutRedirect() {
        assertThat(ids(device("ROUTER", List.of(port("TCP", 80, "http", Map.of("status", 200, "loginForm", true),
                null))))).containsExactly("http.login-cleartext");
        assertThat(ids(device("ROUTER", List.of(port("TCP", 80, "http", Map.of("status", 401,
                "authenticate", "Basic"), null))))).containsExactly("http.login-cleartext");
        assertThat(ids(device("ROUTER", List.of(port("TCP", 80, "http", Map.of("status", 301, "loginForm", true,
                "redirectsToHttps", true), null))))).isEmpty();
        assertThat(ids(device("ROUTER", List.of(port("TCP", 80, "http", Map.of("status", 200), null))))).isEmpty();
        assertThat(ids(device("ROUTER", List.of(port("TCP", 443, "http", Map.of("loginForm", true),
                Map.of("versions", List.of("TLS1.3"))))))).isEmpty();
    }

    @Test
    void tlsAndSmbFindings() {
        List<Detection> legacy = run(device("NAS", List.of(port("TCP", 443, "https", null,
                Map.of("versions", List.of("TLS1.0", "TLS1.1"), "expired", true, "notAfter", "2020-01-01")))));
        assertThat(legacy).extracting(Detection::ruleId).containsExactlyInAnyOrder("tls.legacy-protocol",
                "tls.certificate-expired");
        assertThat(legacy.stream().filter(d -> d.ruleId().equals("tls.legacy-protocol")).findFirst().orElseThrow()
                .severity()).isEqualTo(Severity.MEDIUM); // nothing newer offered
        Detection mixed = run(device("NAS", List.of(port("TCP", 443, "https", null,
                Map.of("versions", List.of("TLS1.2", "TLS1.0")))))).get(0);
        assertThat(mixed.severity()).isEqualTo(Severity.LOW);
        assertThat(ids(device("NAS", List.of(port("TCP", 445, "smb", Map.of("smb1", true), null)))))
                .containsExactly("smb.v1-enabled");
        assertThat(ids(device("NAS", List.of(port("TCP", 445, "smb", Map.of("smb1", false), null))))).isEmpty();
    }

    @Test
    void resolverAndUnknownDeviceRules() {
        PortView dns = port("UDP", 53, "dns", Map.of("recursionAvailable", true, "rcode", 0), null);
        assertThat(ids(device("NAS", List.of(dns)))).containsExactly("dns.open-resolver");
        assertThat(ids(device("ROUTER", List.of(dns)))).isEmpty(); // the router is the home's resolver
        assertThat(ids(device("UNKNOWN_DEVICE", List.of()))).containsExactly("device.unknown");
        assertThat(ids(new DeviceView(UUID.randomUUID(), "UNKNOWN_DEVICE", true, List.of(), Map.of(), List.of(),
                false))).isEmpty(); // the user set a category
    }

    @Test
    void upnpMappingsAreRiskyOnlyForSensitivePortsOrCameras() {
        List<Mapping> mappings = List.of(new Mapping("TCP", 8080, 80, "MOCK web"),
                new Mapping("UDP", 51413, 51413, "MOCK torrent"));
        DeviceView nas = new DeviceView(UUID.randomUUID(), "NAS", false, List.of(), Map.of(), mappings, false);
        List<Detection> found = run(nas);
        assertThat(found).extracting(Detection::ruleId).containsExactly("upnp.exposed-mapping");
        assertThat(found.get(0).port()).isEqualTo(8080);
        assertThat(found.get(0).severity()).isEqualTo(Severity.HIGH);

        DeviceView camera = new DeviceView(UUID.randomUUID(), "IP_CAMERA", false, List.of(), Map.of(), mappings,
                true);
        List<Detection> exposed = run(camera);
        assertThat(exposed).hasSize(2).allMatch(d -> d.severity() == Severity.CRITICAL); // known exploited CVE

        DeviceView router = new DeviceView(UUID.randomUUID(), "ROUTER", false, List.of(),
                Map.of("UPNP_IGD", Map.of("serviceType", "urn:mock:WANIPConnection:1", "portMappings", List.of())),
                List.of(), false);
        assertThat(ids(router)).containsExactly("upnp.igd-enabled");
    }

    @Test
    void portListsAreTheAgentLists() throws Exception {
        Path agent = Path.of("../../agent/go-security-agent/internal/portscan/portlists.json");
        Path backend = Path.of("src/main/resources/findings/portlists.json");
        assertThat(JSON.readTree(Files.readAllBytes(backend))).isEqualTo(JSON.readTree(Files.readAllBytes(agent)));
        PortLists lists = new PortLists(JSON);
        assertThat(lists.contains("QUICK", "TCP", 23)).isTrue();
        assertThat(lists.contains("QUICK", "TCP", 2323)).isFalse();
        assertThat(lists.contains("STANDARD", "TCP", 2323)).isTrue();
        assertThat(lists.contains("DISCOVERY", "TCP", 23)).isFalse();
    }
}

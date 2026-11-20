package com.shsc.devices.fingerprint;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.shsc.devices.fingerprint.FieldResolver.Candidate;
import com.shsc.devices.fingerprint.FieldResolver.Field;
import com.shsc.devices.fingerprint.FieldResolver.Identification;
import com.shsc.devices.fingerprint.FieldResolver.Reliability;
import com.shsc.devices.fingerprint.FieldResolver.Status;
import com.shsc.devices.fingerprint.HostEvidence.PortSeen;
import com.shsc.devices.fingerprint.HostEvidence.Seen;

import tools.jackson.databind.json.JsonMapper;

/**
 * Status VERIFIED / PROBABLE / UNKNOWN of the identity fields (M20, ADR-076) on a reference
 * dataset of [MOCK] devices: no VERIFIED value may be wrong.
 */
class IdentityStatusTest {

    private static final ClassificationRules RULES = new ClassificationRules(JsonMapper.builder().build());

    private static Map<Field, Identification> identify(List<PortSeen> ports, String oui, Seen... observations) {
        HostEvidence host = HostEvidence.of(List.of(observations), ports, oui);
        return FieldResolver.identify(host, RULES.classify(host.signals()));
    }

    @Test
    void declaredValuesAreVerifiedAndDerivedOnesProbable() {
        // MOCK UPnP media renderer: maker, model, product code and firmware from its own descriptor
        Map<Field, Identification> tv = identify(List.of(), "MOCK Chips Ltd",
                new Seen("ARP", "192.168.70.10", "00:11:22:00:70:10", null, null),
                new Seen("SSDP", "192.168.70.10", null, null, Map.of("manufacturer", "MOCK Vision Inc.",
                        "modelName", "MockTV", "modelNumber", "MTV-55", "firmwareVersion", "4.2.1")));
        assertThat(tv.get(Field.IP).status()).isEqualTo(Status.VERIFIED); // observed directly (ARP)
        assertThat(tv.get(Field.MANUFACTURER).value()).isEqualTo("MOCK Vision Inc.");
        assertThat(tv.get(Field.MANUFACTURER).status()).isEqualTo(Status.VERIFIED);
        assertThat(tv.get(Field.MODEL).value()).isEqualTo("MockTV MTV-55");
        assertThat(tv.get(Field.MODEL).status()).isEqualTo(Status.VERIFIED);
        assertThat(tv.get(Field.PRODUCT_CODE).value()).isEqualTo("MTV-55");
        assertThat(tv.get(Field.FIRMWARE).value()).isEqualTo("4.2.1");
        assertThat(tv.get(Field.FIRMWARE).status()).isEqualTo(Status.VERIFIED);
        // CPE derived from maker + model: ambiguous for IoT, never VERIFIED automatically
        assertThat(tv.get(Field.CPE).value()).isEqualTo("cpe:2.3:h:mock_vision:mocktv_mtv-55:*:*:*:*:*:*:*:*");
        assertThat(tv.get(Field.CPE).status()).isEqualTo(Status.PROBABLE);
        // category from rules: PROBABLE until the user sets it
        if (tv.containsKey(Field.DEVICE_TYPE)) {
            assertThat(tv.get(Field.DEVICE_TYPE).status()).isEqualTo(Status.PROBABLE);
        }

        // MOCK printer: model and firmware from IPP
        Map<Field, Identification> printer = identify(List.of(new PortSeen("TCP", 631, "ipp", "MOCK LaserJet 100",
                "CONFIRMED", Map.of("makeAndModel", "MOCK LaserJet 100", "firmware", "20231105"))), null,
                new Seen("ARP", "192.168.70.20", "00:11:22:00:70:20", null, null));
        assertThat(printer.get(Field.MODEL).status()).isEqualTo(Status.VERIFIED);
        assertThat(printer.get(Field.FIRMWARE).value()).isEqualTo("20231105");
        assertThat(printer.get(Field.FIRMWARE).status()).isEqualTo(Status.VERIFIED);

        // MOCK plug with firmware in the mDNS TXT record, maker only from the OUI
        Map<Field, Identification> plug = identify(List.of(), "MOCK Espressif",
                new Seen("ARP", "192.168.70.30", "00:11:22:00:70:30", null, null),
                new Seen("MDNS", "192.168.70.30", null, "mock-plug.local", Map.of("txt", Map.of("fw", "1.14.0"))));
        assertThat(plug.get(Field.FIRMWARE).status()).isEqualTo(Status.VERIFIED);
        assertThat(plug.get(Field.HOSTNAME).status()).isEqualTo(Status.VERIFIED); // announced by the device
        assertThat(plug.get(Field.MANUFACTURER).status()).isEqualTo(Status.PROBABLE); // network card maker
        assertThat(plug).doesNotContainKeys(Field.MODEL, Field.PRODUCT_CODE, Field.CPE); // UNKNOWN: nothing invented
    }

    @Test
    void sourcesWithTheSameOriginNeverVerify() {
        // the two router tables repeat the same DHCP announcement of the device: one origin
        Map<Field, Identification> host = identify(List.of(), null,
                new Seen("TR064", "192.168.70.40", "00:11:22:00:70:40", "mock-phone", Map.of()),
                new Seen("SNMP", "192.168.70.40", "00:11:22:00:70:40", "mock-phone", Map.of()),
                new Seen("RDNS", "192.168.70.40", null, "mock-phone.lan", Map.of()));
        assertThat(host.get(Field.HOSTNAME).value()).isEqualTo("mock-phone");
        assertThat(host.get(Field.HOSTNAME).status()).isEqualTo(Status.PROBABLE);

        Map<String, Candidate> sameOrigin = group(new Candidate("v", "TR064", Reliability.H, "X", false),
                new Candidate("v", "SNMP", Reliability.H, "X", false));
        assertThat(FieldResolver.status(sameOrigin, false)).isEqualTo(Status.PROBABLE);
        Map<String, Candidate> independent = group(new Candidate("v", "A", Reliability.M, "A", false),
                new Candidate("v", "B", Reliability.M, "B", false));
        assertThat(FieldResolver.status(independent, false)).isEqualTo(Status.VERIFIED);
        // a heuristic (L) never counts as an independent confirmation
        Map<String, Candidate> heuristic = group(new Candidate("v", "A", Reliability.M, "A", false),
                new Candidate("v", "TTL", Reliability.L, "TTL", false));
        assertThat(FieldResolver.status(heuristic, false)).isEqualTo(Status.PROBABLE);
        assertThat(FieldResolver.status(independent, true)).isEqualTo(Status.PROBABLE);
    }

    @Test
    void conflictingSourcesGiveProbable() {
        Map<Field, Identification> host = identify(List.of(), null,
                new Seen("ARP", "192.168.70.50", "00:11:22:00:70:50", null, null),
                new Seen("SSDP", "192.168.70.50", null, null, Map.of("manufacturer", "Sony (MOCK)")),
                new Seen("MDNS", "192.168.70.50", null, null, Map.of("txt", Map.of("manufacturer", "Google (MOCK)"))));
        assertThat(host.get(Field.MANUFACTURER).conflict()).isTrue();
        assertThat(host.get(Field.MANUFACTURER).status()).isEqualTo(Status.PROBABLE);
    }

    @Test
    void homeAssistantIsAnIndependentOriginButNotADeclaration() {
        HostEvidence host = HostEvidence.of(List.of(new Seen("ARP", "192.168.70.60", "00:11:22:00:70:60", null,
                null)), null).withHomeAssistant("MOCK Shelly", "MOCK Plug S", "20240101-1.2.3");
        Map<Field, Identification> ids = FieldResolver.identify(host, RULES.classify(host.signals()));
        assertThat(ids.get(Field.FIRMWARE).value()).isEqualTo("20240101-1.2.3");
        assertThat(ids.get(Field.FIRMWARE).status()).isEqualTo(Status.PROBABLE);
        assertThat(ids.get(Field.MODEL).status()).isEqualTo(Status.PROBABLE);
    }

    @Test
    void userConfirmationWinsAndKeepsTheConflictVisible() {
        Identification scanned = identify(List.of(), null,
                new Seen("ARP", "192.168.70.70", "00:11:22:00:70:70", null, null),
                new Seen("SSDP", "192.168.70.70", null, null, Map.of("manufacturer", "MOCK Vision",
                        "firmwareVersion", "1.0"))).get(Field.FIRMWARE);
        Identification same = FieldResolver.confirmed(Field.FIRMWARE, "1.0", scanned);
        assertThat(same.status()).isEqualTo(Status.VERIFIED);
        assertThat(same.conflict()).isFalse();
        Identification other = FieldResolver.confirmed(Field.FIRMWARE, "2.0", scanned);
        assertThat(other.value()).isEqualTo("2.0");
        assertThat(other.status()).isEqualTo(Status.VERIFIED);
        assertThat(other.conflict()).isTrue();
        assertThat(other.sources()).anyMatch(s -> s.source().equals("SSDP") && !s.agrees());
    }

    @Test
    void cpeComponentsAreEscaped() {
        assertThat(FieldResolver.cpeComponent("TP-Link")).isEqualTo("tp-link");
        assertThat(FieldResolver.cpeComponent("DS920+ (MOCK)")).isEqualTo("ds920\\+_\\(mock\\)");
        assertThat(FieldResolver.cpeComponent("ÜberCam")).isEqualTo("bercam");
    }

    private static Map<String, Candidate> group(Candidate... candidates) {
        Map<String, Candidate> out = new LinkedHashMap<>();
        for (Candidate c : candidates) {
            out.put(c.source(), c);
        }
        return out;
    }
}

package com.shsc.devices.fingerprint;

import static org.assertj.core.api.Assertions.assertThat;

import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.shsc.devices.fingerprint.FieldResolver.Field;
import com.shsc.devices.fingerprint.FieldResolver.Identification;
import com.shsc.devices.fingerprint.HostEvidence.Seen;

import tools.jackson.databind.json.JsonMapper;

/** Per-field confidence (docs/07 §3), basic OS fingerprint and randomized MACs. [MOCK] data. */
class FieldResolverTest {

    private static final ClassificationRules RULES = new ClassificationRules(JsonMapper.builder().build());

    private static Map<Field, Identification> identify(String oui, Seen... observations) {
        HostEvidence host = HostEvidence.of(List.of(observations), oui);
        return FieldResolver.identify(host, RULES.classify(host.signals()));
    }

    @Test
    void addressesFromArpAndNamesFromTheRouterAreHigh() {
        Map<Field, Identification> f = identify(null,
                new Seen("ARP", "192.168.1.30", "00:11:22:33:44:30", null, null),
                new Seen("TR064", "192.168.1.30", "00:11:22:33:44:30", "MOCK-TV", Map.of("source", "router")),
                new Seen("MDNS", "192.168.1.30", null, "living-room-tv.local", Map.of("selfDeclared", true)));
        assertThat(f.get(Field.IP).confidence()).isEqualTo(Confidence.HIGH);
        assertThat(f.get(Field.MAC).confidence()).isEqualTo(Confidence.HIGH);
        Identification name = f.get(Field.HOSTNAME);
        assertThat(name.value()).isEqualTo("MOCK-TV");
        assertThat(name.confidence()).isEqualTo(Confidence.HIGH);
        assertThat(name.conflict()).isFalse(); // names are variants, every one is kept with its source
        assertThat(name.sources()).extracting(FieldResolver.Source::value).contains("living-room-tv.local");
        assertThat(f).doesNotContainKeys(Field.MANUFACTURER, Field.MODEL, Field.OS, Field.FIRMWARE, Field.DEVICE_TYPE);
    }

    @Test
    void theMakerOfTheNetworkCardAloneIsLowAndConcordantDeclarationsAreMedium() {
        Seen arp = new Seen("ARP", "192.168.1.31", "00:11:32:00:00:31", null, null);
        assertThat(identify("MOCK Synology Incorporated", arp).get(Field.MANUFACTURER).confidence())
                .isEqualTo(Confidence.LOW);

        Map<Field, Identification> f = identify("Synology Incorporated", arp,
                new Seen("SSDP", "192.168.1.31", null, null, Map.of("manufacturer", "Synology Inc.",
                        "modelName", "DS220+")),
                new Seen("MDNS", "192.168.1.31", null, null, Map.of("txt", Map.of("vendor", "Synology"))));
        Identification maker = f.get(Field.MANUFACTURER);
        assertThat(maker.confidence()).isEqualTo(Confidence.MEDIUM); // M + M + L concordant, no H
        assertThat(maker.conflict()).isFalse();
        assertThat(f.get(Field.MODEL).value()).isEqualTo("DS220+");
    }

    @Test
    void conflictingDeclarationsLowerTheConfidenceAndAreRecorded() {
        Map<Field, Identification> f = identify(null,
                new Seen("ARP", "192.168.1.32", "00:11:22:33:44:32", null, null),
                new Seen("SSDP", "192.168.1.32", null, null, Map.of("manufacturer", "Sony")),
                new Seen("MDNS", "192.168.1.32", null, null, Map.of("txt", Map.of("manufacturer", "Google"))));
        Identification maker = f.get(Field.MANUFACTURER);
        assertThat(maker.conflict()).isTrue();
        assertThat(maker.confidence()).isEqualTo(Confidence.LOW);
        assertThat(maker.sources()).anyMatch(s -> !s.agrees());
    }

    @Test
    void theTtlAloneIsAtMostLowAndTtl64AloneNamesNoSystem() {
        Seen arp = new Seen("ARP", "192.168.1.40", "00:11:22:33:44:40", null, null);
        Identification windows = identify(null, arp, new Seen("ICMP", "192.168.1.40", null, null, Map.of("ttl", 128)))
                .get(Field.OS);
        assertThat(windows.value()).isEqualTo("WINDOWS");
        assertThat(windows.confidence()).isEqualTo(Confidence.LOW);

        assertThat(identify(null, arp, new Seen("ICMP", "192.168.1.40", null, null, Map.of("ttl", 64))))
                .doesNotContainKey(Field.OS);

        // NetBIOS + default Windows name + TTL 128: weak, concordant, independent sources
        Identification pc = identify(null, arp, new Seen("ICMP", "192.168.1.40", null, null, Map.of("ttl", 127)),
                new Seen("NETBIOS", "192.168.1.40", null, "DESKTOP-AB12CD3", Map.of("workgroup", "WORKGROUP")))
                .get(Field.OS);
        assertThat(pc.value()).isEqualTo("WINDOWS");
        assertThat(pc.confidence()).isEqualTo(Confidence.MEDIUM);
    }

    @Test
    void ttl64SupportsTheUnixLikeSystemNamedByAnotherSource() {
        Identification mac = identify(null, new Seen("ARP", "192.168.1.41", "00:11:22:33:44:41", null, null),
                new Seen("ICMP", "192.168.1.41", null, null, Map.of("ttl", 64)),
                new Seen("MDNS", "192.168.1.41", null, "mock-mbp", Map.of("txt", Map.of("model", "MacBookPro18,3"))))
                .get(Field.OS);
        assertThat(mac.value()).isEqualTo("MACOS");
        assertThat(mac.confidence()).isEqualTo(Confidence.MEDIUM);
        assertThat(mac.sources()).extracting(FieldResolver.Source::source).contains("MDNS", "TTL");
    }

    @Test
    void randomizedMacsAreRecognizedAndAnUnknownDeviceHasLowOverallConfidence() {
        assertThat(HostEvidence.locallyAdministered("da:a1:19:00:00:01")).isTrue();
        assertThat(HostEvidence.locallyAdministered("00:11:22:00:00:01")).isFalse();
        HostEvidence phone = HostEvidence.of(List.of(new Seen("ARP", "192.168.1.50", "DA:A1:19:00:00:01", null, null)),
                null);
        assertThat(phone.macRandomized()).isTrue();
        assertThat(phone.mac()).isEqualTo("da:a1:19:00:00:01");

        Map<Field, Identification> unknown = identify(null,
                new Seen("ARP", "192.168.1.51", "00:11:22:33:44:51", null, null));
        assertThat(FieldResolver.overall(unknown)).isEqualTo(Confidence.LOW);
    }
}

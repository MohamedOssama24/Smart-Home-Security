package com.shsc.devices.fingerprint;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import com.shsc.devices.fingerprint.ClassificationRules.Classification;
import com.shsc.devices.fingerprint.ClassificationRules.Condition;
import com.shsc.devices.fingerprint.ClassificationRules.RuleFile;
import com.shsc.devices.fingerprint.ClassificationRules.RulesetFile;
import com.shsc.devices.fingerprint.HostEvidence.Seen;

import tools.jackson.databind.json.JsonMapper;

/**
 * The repository ruleset (fingerprint/rules.json): positive cases, and negative cases where
 * only weak hints, or hints from a single source, must never be enough. [MOCK] data.
 */
class ClassificationRulesTest {

    private static final ClassificationRules RULES = new ClassificationRules(JsonMapper.builder().build());

    private static Classification classify(String oui, Seen... observations) {
        return RULES.classify(HostEvidence.of(List.of(observations), oui).signals());
    }

    private static Seen arp(String ip) {
        return new Seen("ARP", ip, "00:11:22:33:44:55", null, null);
    }

    private static Seen mdns(String ip, String hostname, List<String> services, Map<String, String> txt) {
        List<Map<String, Object>> list = new ArrayList<>();
        services.forEach(s -> list.add(Map.of("type", s)));
        return new Seen("MDNS", ip, null, hostname, Map.of("selfDeclared", true, "services", list, "txt", txt));
    }

    private static Seen ssdp(String ip, Map<String, Object> details) {
        return new Seen("SSDP", ip, null, null, details);
    }

    @Test
    void printerAnnouncingIppIsAPrinterConfirmedByAnIndependentSource() {
        Classification alone = classify(null, arp("192.168.1.10"),
                mdns("192.168.1.10", "mock-printer", List.of("_ipp._tcp"), Map.of()));
        assertThat(alone.category()).isEqualTo(DeviceCategory.PRINTER);
        assertThat(alone.confidence()).isEqualTo(Confidence.MEDIUM); // one STRONG evidence, not confirmed

        Classification confirmed = classify(null, arp("192.168.1.10"),
                mdns("192.168.1.10", "mock-printer", List.of("_ipp._tcp"), Map.of()),
                ssdp("192.168.1.10", Map.of("deviceType", "urn:schemas-upnp-org:device:Printer:1")));
        assertThat(confirmed.category()).isEqualTo(DeviceCategory.PRINTER);
        assertThat(confirmed.confidence()).isEqualTo(Confidence.HIGH);
        assertThat(confirmed.rulesetVersion()).isEqualTo(RULES.version());
    }

    @Test
    void theRouterOfTheOwnerIntegrationIsARouter() {
        Classification c = classify(null, arp("192.168.1.1"),
                new Seen("TR064", "192.168.1.1", null, null, Map.of("router", true, "manufacturer", "MOCK AVM")),
                new Seen("UPNP_IGD", "192.168.1.1", null, null, Map.of("selfDeclared", true)));
        assertThat(c.category()).isEqualTo(DeviceCategory.ROUTER);
        assertThat(c.confidence()).isEqualTo(Confidence.HIGH);
    }

    @Test
    void onlyTheMakerOfTheNetworkCardIsNeverEnough() {
        Classification c = classify("MOCK Hikvision Digital Technology", arp("192.168.1.20"));
        assertThat(c.category()).isEqualTo(DeviceCategory.UNKNOWN_DEVICE);
        assertThat(c.confidence()).isNull();
        assertThat(c.matches()).extracting(m -> m.ruleId()).containsExactly("camera.oui"); // seen, but weak
    }

    @Test
    void twoWeakHintsAreNotEnoughEither() {
        Classification c = classify("MOCK Hikvision Digital Technology", arp("192.168.1.20"),
                new Seen("RDNS", "192.168.1.20", null, "camera-20.lan", null));
        assertThat(c.matches()).hasSize(2);
        assertThat(c.category()).isEqualTo(DeviceCategory.UNKNOWN_DEVICE);
    }

    @Test
    void twoModerateHintsFromTheSameSourceAreNotIndependent() {
        // _adisk service and "diskstation" name: both declared over mDNS
        Classification same = classify(null, arp("192.168.1.30"),
                mdns("192.168.1.30", "DiskStation", List.of("_adisk._tcp"), Map.of()));
        assertThat(same.matches()).extracting(m -> m.ruleId()).contains("nas.mdns-adisk", "nas.hostname");
        assertThat(same.category()).isEqualTo(DeviceCategory.UNKNOWN_DEVICE);

        // the UPnP description is a second, independent source
        Classification independent = classify(null, arp("192.168.1.30"),
                mdns("192.168.1.30", "DiskStation", List.of("_adisk._tcp"), Map.of()),
                ssdp("192.168.1.30", Map.of("modelName", "MOCK DiskStation DS220+")));
        assertThat(independent.category()).isEqualTo(DeviceCategory.NAS);
        assertThat(independent.confidence()).isEqualTo(Confidence.MEDIUM);
    }

    @Test
    void weakHintsCombinedFromIndependentSourcesBecomeModerate() {
        Seen hap = mdns("192.168.1.40", null, List.of("_hap._tcp"), Map.of());
        assertThat(classify(null, arp("192.168.1.40"), hap).category()).isEqualTo(DeviceCategory.UNKNOWN_DEVICE);
        Classification c = classify("MOCK Espressif Inc.", arp("192.168.1.40"), hap);
        assertThat(c.category()).isEqualTo(DeviceCategory.IOT);
        assertThat(c.confidence()).isEqualTo(Confidence.MEDIUM);
    }

    @Test
    void appleModelDeclaredOverMdnsIsStrong() {
        Classification phone = classify(null, mdns("192.168.1.50", "Mario-iPhone", List.of("_apple-mobdev2._tcp"),
                Map.of("model", "iPhone15,2")));
        assertThat(phone.category()).isEqualTo(DeviceCategory.SMARTPHONE);
        assertThat(phone.confidence()).isEqualTo(Confidence.MEDIUM); // the name comes from mDNS too
    }

    @Test
    void conflictingCategoriesLowerTheConfidenceOrLeaveTheDeviceUnknown() {
        // printer: STRONG + MODERATE (two sources); TV model: STRONG → printer wins, one level lower
        Classification lower = classify(null, arp("192.168.1.60"),
                mdns("192.168.1.60", null, List.of("_ipp._tcp"), Map.of("md", "MOCK Chromecast")),
                ssdp("192.168.1.60", Map.of("deviceType", "urn:schemas-upnp-org:device:Printer:1")));
        assertThat(lower.category()).isEqualTo(DeviceCategory.PRINTER);
        assertThat(lower.confidence()).isEqualTo(Confidence.MEDIUM);
        assertThat(lower.conflicts()).containsExactly(DeviceCategory.SMART_TV);

        // same score for two categories: not decided
        Classification tie = classify(null, arp("192.168.1.61"),
                mdns("192.168.1.61", null, List.of("_ipp._tcp"), Map.of("md", "MOCK Chromecast")));
        assertThat(tie.category()).isEqualTo(DeviceCategory.UNKNOWN_DEVICE);
        assertThat(tie.conflicts()).containsExactlyInAnyOrder(DeviceCategory.PRINTER, DeviceCategory.SMART_TV);
    }

    @Test
    void anInvalidRulesetIsRefusedAtStartup() {
        Map<Strength, Integer> weights = Map.of(Strength.STRONG, 60, Strength.MODERATE, 30, Strength.WEAK, 10);
        RuleFile rule = new RuleFile("x", DeviceCategory.NAS, Strength.WEAK, List.of(new Condition("oui", "x")), null);
        // a weak hint reaching the threshold alone
        assertThatThrownBy(() -> new ClassificationRules(new RulesetFile("1", null, 10, weights, List.of(rule))))
                .isInstanceOf(IllegalStateException.class);
        // duplicated rule id
        assertThatThrownBy(() -> new ClassificationRules(new RulesetFile("1", null, 50, weights, List.of(rule, rule))))
                .isInstanceOf(IllegalStateException.class);
        // a rule cannot conclude "unknown"
        RuleFile unknown = new RuleFile("u", DeviceCategory.UNKNOWN_DEVICE, Strength.STRONG,
                List.of(new Condition("oui", "x")), null);
        assertThatThrownBy(() -> new ClassificationRules(new RulesetFile("1", null, 50, weights, List.of(unknown))))
                .isInstanceOf(IllegalStateException.class);
    }
}

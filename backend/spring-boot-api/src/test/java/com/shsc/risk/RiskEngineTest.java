package com.shsc.risk;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.within;

import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.UUID;

import org.junit.jupiter.api.Test;

import com.shsc.risk.RiskEngine.Coverage;
import com.shsc.risk.RiskEngine.CoverageInput;
import com.shsc.risk.RiskEngine.DeviceInput;
import com.shsc.risk.RiskEngine.FindingInput;
import com.shsc.risk.RiskEngine.Result;

/** Risk engine edge cases (Milestone 11): pure computation, [MOCK] findings and devices. */
class RiskEngineTest {

    private static final UUID ROUTER = UUID.fromString("00000000-0000-0000-0000-00000000a001");
    private static final UUID UNKNOWN = UUID.fromString("00000000-0000-0000-0000-00000000a002");
    private static final UUID LAPTOP = UUID.fromString("00000000-0000-0000-0000-00000000a003");
    private static final Map<UUID, DeviceInput> DEVICES = Map.of(
            ROUTER, new DeviceInput(ROUTER, "mock-router", "192.168.60.1", "ROUTER"),
            UNKNOWN, new DeviceInput(UNKNOWN, "mock-unknown", "192.168.60.30", "UNKNOWN_DEVICE"),
            LAPTOP, new DeviceInput(LAPTOP, "mock-laptop", "192.168.60.40", "LAPTOP"));

    private static final Coverage FULL = RiskEngine.coverage(new CoverageInput("STANDARD", 3, 3, Set.of(), true));

    private static int ids;

    private static FindingInput finding(UUID device, String rule, String severity, String type, String confidence,
            String status, String cve, boolean kev) {
        return new FindingInput(new UUID(0, ++ids), device, rule, "findings.rule." + rule + ".title", Map.of(),
                severity, type, confidence, status, cve, kev);
    }

    private static FindingInput telnet(UUID device) {
        return finding(device, "telnet.open", "HIGH", "SUSPICIOUS_CONFIGURATION", "HIGH", "OPEN", null, false);
    }

    @Test
    void coverageWeighsHostsDepthTechniquesAndRouter() {
        assertThat(FULL.value()).isCloseTo(0.9625, within(0.001)); // 0.40 + 0.25 × 0.85 + 0.20 + 0.15
        Coverage partial = RiskEngine.coverage(new CoverageInput("QUICK", 4, 3, Set.of("MDNS_UNAVAILABLE",
                "LATE_UPLOAD"), true));
        assertThat(partial.value()).isCloseTo(0.30 + 0.15 + 0.16 + 0.15, within(1e-9));
        assertThat(partial.detail().get("techniques")).isEqualTo(Map.of("ARP", true, "ICMP", true, "MDNS", false,
                "SSDP", true));
        // nothing discovered: no host ratio, never a division by zero
        assertThat(RiskEngine.coverage(new CoverageInput("QUICK", 0, 0, Set.of(), false)).value())
                .isCloseTo(0.35, within(1e-9));
    }

    @Test
    void noFindingsWithFullCoverageIsExcellent() {
        Result r = RiskEngine.evaluate(List.of(), DEVICES, FULL, true);
        assertThat(r.score()).isEqualTo(100);
        assertThat(r.riskLevel()).isEqualTo("LOW");
        assertThat(r.rating()).isEqualTo("EXCELLENT");
        assertThat(r.provisional()).isFalse();
    }

    @Test
    void lowCoverageCapsTheScoreAndMarksItProvisional() {
        // QUICK, ARP only, half of the hosts: 0.20 + 0.15 + 0.08 = 0.43 < 0.6
        Coverage low = RiskEngine.coverage(new CoverageInput("QUICK", 4, 2, Set.of("ICMP_UNAVAILABLE",
                "MDNS_UNAVAILABLE", "SSDP_UNAVAILABLE"), false));
        assertThat(low.value()).isCloseTo(0.43, within(1e-9));
        Result r = RiskEngine.evaluate(List.of(), DEVICES, low, true);
        assertThat(r.provisional()).isTrue();
        assertThat(r.uncappedScore()).isEqualTo(100);
        assertThat(r.score()).isEqualTo(70); // nothing found is not "safe" when little was looked at
        assertThat(r.riskLevel()).isEqualTo("MEDIUM");
        assertThat(r.rating()).isEqualTo("FAIR");

        // 0.6 ≤ coverage < 0.8: not capped, but never "excellent"
        Coverage medium = RiskEngine.coverage(new CoverageInput("QUICK", 4, 4, Set.of(), false)); // 0.75
        Result good = RiskEngine.evaluate(List.of(), DEVICES, medium, true);
        assertThat(good.provisional()).isFalse();
        assertThat(good.score()).isEqualTo(100);
        assertThat(good.rating()).isEqualTo("GOOD");
    }

    @Test
    void discoveryScanHasNoScore() {
        Coverage discovery = RiskEngine.coverage(new CoverageInput("DISCOVERY", 3, 0, Set.of(), false));
        Result r = RiskEngine.evaluate(List.of(telnet(ROUTER)), DEVICES, discovery, false);
        assertThat(r.score()).isNull();
        assertThat(r.riskLevel()).isNull();
        assertThat(r.rating()).isNull();
        assertThat(r.notComputedReason()).isEqualTo(RiskEngine.PORT_SCAN_REQUIRED);
        assertThat(r.deductions()).isEmpty();
    }

    @Test
    void unknownDeviceIsNotPenalizedAsSuch() {
        FindingInput unknown = finding(UNKNOWN, "device.unknown", "INFORMATIONAL", "UNVERIFIED_INFORMATION", "LOW",
                "OPEN", null, false);
        Result alone = RiskEngine.evaluate(List.of(unknown), DEVICES, FULL, true);
        assertThat(alone.score()).isEqualTo(100);
        assertThat(alone.notScored()).isEqualTo(1);
        assertThat(alone.deductions()).isEmpty();

        // what it exposes counts, with the neutral criticality 1.0: 15 × 0.5 × 1.0 = 7.5
        Result exposed = RiskEngine.evaluate(List.of(unknown, telnet(UNKNOWN)), DEVICES, FULL, true);
        assertThat(exposed.deductions()).singleElement().satisfies(d -> {
            assertThat(d.criticality()).isEqualTo(1.0);
            assertThat(d.value()).isEqualTo(7.5);
        });
        assertThat(exposed.score()).isEqualTo(92); // 92.5 rounded down: a deduction is never rounded away
    }

    @Test
    void factorsMultiplyAndOneDeviceIsCapped() {
        FindingInput kevCve = finding(ROUTER, "cve.version-match", "CRITICAL", "CONFIRMED_VULNERABILITY", "HIGH",
                "OPEN", "CVE-2099-1001", true);
        FindingInput mapping = finding(ROUTER, "upnp.exposed-mapping", "HIGH", "SUSPICIOUS_CONFIGURATION", "HIGH",
                "ACKNOWLEDGED", null, false);
        Result r = RiskEngine.evaluate(List.of(kevCve, mapping), DEVICES, FULL, true);
        assertThat(r.deductions().get(0).value()).isCloseTo(87.75, within(0.01)); // 30 × 1.0 × 1.0 × 1.3 router × 1.5 exposed × 1.5 KEV
        assertThat(r.deductions().get(1).value()).isCloseTo(14.63, within(0.01)); // 15 × 0.5 × 1.3 × 1.5
        assertThat(r.devices()).singleElement().satisfies(t -> {
            assertThat(t.exposed()).isTrue();
            assertThat(t.capped()).isTrue();
            assertThat(t.applied()).isEqualTo(45.0);
        });
        assertThat(r.score()).isEqualTo(55); // one device alone does not take the score to zero…
        assertThat(r.riskLevel()).isEqualTo("HIGH");
        assertThat(r.rating()).isEqualTo("POOR");

        // …but several devices do; the laptop counts 1.1
        Result many = RiskEngine.evaluate(List.of(kevCve, mapping,
                finding(UNKNOWN, "cve.version-match", "CRITICAL", "CONFIRMED_VULNERABILITY", "HIGH", "OPEN",
                        "CVE-2099-1002", true),
                finding(LAPTOP, "cve.version-match", "CRITICAL", "CONFIRMED_VULNERABILITY", "HIGH", "OPEN",
                        "CVE-2099-1004", false)),
                DEVICES, FULL, true);
        assertThat(many.devices()).extracting(t -> t.applied()).containsExactly(45.0, 45.0, 33.0);
        assertThat(many.score()).isZero();
        assertThat(many.riskLevel()).isEqualTo("CRITICAL");
    }

    @Test
    void falsePositivesAndAcceptedRisksAreShownApart() {
        FindingInput falsePositive = finding(ROUTER, "cve.version-match", "CRITICAL", "CONFIRMED_VULNERABILITY",
                "HIGH", "FALSE_POSITIVE", "CVE-2099-1001", true);
        FindingInput acceptedMapping = finding(ROUTER, "upnp.exposed-mapping", "HIGH", "SUSPICIOUS_CONFIGURATION",
                "HIGH", "ACCEPTED_RISK", null, false);
        FindingInput potential = finding(ROUTER, "cve.version-match", "MEDIUM", "POTENTIAL_RISK", "MEDIUM", "OPEN",
                "CVE-2099-1003", false);
        Result r = RiskEngine.evaluate(List.of(falsePositive, acceptedMapping, potential), DEVICES, FULL, true);
        assertThat(r.excluded()).extracting(e -> e.status()).containsExactlyInAnyOrder("FALSE_POSITIVE",
                "ACCEPTED_RISK");
        // only the potential risk counts: 6 × 0.6 × 0.8 × 1.3 = 3.744, not exposed (mapping accepted)
        assertThat(r.deductions()).singleElement().satisfies(d -> {
            assertThat(d.exposure()).isEqualTo(1.0);
            assertThat(d.value()).isEqualTo(3.74);
        });
        assertThat(r.score()).isEqualTo(96);
    }

    @Test
    void riskLevelBoundaries() {
        assertThat(RiskEngine.level(100)).isEqualTo("LOW");
        assertThat(RiskEngine.level(85)).isEqualTo("LOW");
        assertThat(RiskEngine.level(84)).isEqualTo("MEDIUM");
        assertThat(RiskEngine.level(65)).isEqualTo("MEDIUM");
        assertThat(RiskEngine.level(64)).isEqualTo("HIGH");
        assertThat(RiskEngine.level(40)).isEqualTo("HIGH");
        assertThat(RiskEngine.level(39)).isEqualTo("CRITICAL");
        assertThat(RiskEngine.level(0)).isEqualTo("CRITICAL");
    }
}

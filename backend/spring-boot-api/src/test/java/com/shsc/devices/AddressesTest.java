package com.shsc.devices;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.junit.jupiter.api.Test;

import com.shsc.devices.Addresses.Info;
import com.shsc.devices.Addresses.InterfaceId;
import com.shsc.devices.Addresses.Scope;
import com.shsc.devices.DeviceFingerprinter.Group;
import com.shsc.scans.ScanRepository.Observation;

/** Address classification, EUI-64 MAC derivation and grouping of addresses without MAC (M19). [MOCK] data. */
class AddressesTest {

    @Test
    void classifiesFamilyAndScope() {
        assertThat(info("192.168.1.10").scope()).isEqualTo(Scope.PRIVATE);
        assertThat(info("192.168.1.10").family()).isEqualTo(4);
        assertThat(info("169.254.3.4").scope()).isEqualTo(Scope.LINK_LOCAL);
        assertThat(info("8.8.8.8").scope()).isEqualTo(Scope.PUBLIC);
        assertThat(info("fe80::1c2d:3e4f:5a6b:7c8d").scope()).isEqualTo(Scope.LINK_LOCAL);
        assertThat(info("fd00:61::10").scope()).isEqualTo(Scope.UNIQUE_LOCAL);
        assertThat(info("2001:db8::10").scope()).isEqualTo(Scope.GLOBAL);
        assertThat(info("ff02::1").scope()).isEqualTo(Scope.MULTICAST);
        assertThat(info("::1").scope()).isEqualTo(Scope.LOOPBACK);
        assertThat(info("192.168.1.10").interfaceId()).isNull();
    }

    @Test
    void derivesTheMacOfEui64Identifiers() {
        // 00:11:22:00:61:10 → 0211:22ff:fe00:6110 (universal/local bit inverted)
        Info eui = info("fe80::211:22ff:fe00:6110");
        assertThat(eui.interfaceId()).isEqualTo(InterfaceId.EUI64);
        assertThat(eui.eui64Mac()).isEqualTo("00:11:22:00:61:10");
        assertThat(eui.ephemeral()).isFalse();

        Info random = info("2001:db8::1c2d:3e4f:5a6b:7c8d");
        assertThat(random.interfaceId()).isEqualTo(InterfaceId.RANDOM);
        assertThat(random.eui64Mac()).isNull();
        assertThat(random.ephemeral()).isTrue();
        // a random identifier in a ULA / link-local prefix is not pruned (stable inside the home)
        assertThat(info("fd00:61::1c2d:3e4f:5a6b:7c8d").ephemeral()).isFalse();
    }

    @Test
    void rejectsWhatIsNotAnAddressLiteral() {
        assertThat(Addresses.classify("printer.lan")).isEmpty();
        assertThat(Addresses.classify("1234")).isEmpty();
        assertThat(Addresses.classify("")).isEmpty();
        assertThat(Addresses.classify(null)).isEmpty();
    }

    @Test
    void eui64AddressesWithoutMacJoinTheirInterface() {
        String mac = "00:11:22:00:61:10";
        List<Observation> all = List.of(
                obs("192.168.61.10", mac),
                obs("fe80::211:22ff:fe00:6110", null),      // EUI-64 of a MAC seen in the scan
                obs("fe80::211:22ff:fe00:6199", null),      // EUI-64 of a MAC known in the home
                obs("fe80::211:22ff:fe00:6177", null),      // EUI-64 of an unknown MAC: own group
                obs("fd00:61::1c2d:3e4f:5a6b:7c8d", null)); // random identifier: own group
        List<Group> groups = DeviceFingerprinter.group(all, Set.of("00:11:22:00:61:99"));

        assertThat(groups).hasSize(4);
        assertThat(groups.get(0).mac()).isEqualTo(mac);
        assertThat(groups.get(0).observations()).extracting(Observation::ip)
                .containsExactly("192.168.61.10", "fe80::211:22ff:fe00:6110");
        assertThat(groups.get(1).mac()).isEqualTo("00:11:22:00:61:99");
        assertThat(groups.get(2).mac()).isNull();
        assertThat(groups.get(3).mac()).isNull();
    }

    @Test
    void aPingOnlyHostAtTheAddressOfAKnownDeviceIsThatDevice() {
        // [MOCK] .56 answers ping only; .57 answers ping only but its known MAC is seen at .80 in this scan
        List<Group> groups = DeviceFingerprinter.group(List.of(
                obs("192.168.61.56", null), obs("192.168.61.57", null), obs("192.168.61.80", "00:11:22:00:61:57"),
                obs("192.168.61.58", null)), Set.of());
        List<Group> adopted = DeviceFingerprinter.adoptKnownMac(groups,
                Map.of("192.168.61.56", "9E:4D:29:74:3E:74", "192.168.61.57", "00:11:22:00:61:57"));

        assertThat(adopted).extracting(Group::mac)
                .containsExactly("9e:4d:29:74:3e:74", null, "00:11:22:00:61:57", null);
    }

    private static Info info(String address) {
        return Addresses.classify(address).orElseThrow();
    }

    private static Observation obs(String ip, String mac) {
        return new Observation(ip, mac, mac != null ? "ARP" : "ICMP", "eth0", null, null, Instant.now());
    }
}

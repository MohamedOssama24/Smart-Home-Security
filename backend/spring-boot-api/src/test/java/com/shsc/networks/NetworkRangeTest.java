package com.shsc.networks;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.ValueSource;

import com.shsc.shared.web.ApiException;

/** Validation of declared networks: only private ranges of bounded size, never name lookups. */
class NetworkRangeTest {

    @ParameterizedTest
    @CsvSource({
        "192.168.1.0/24, 192.168.1.0/24, 4",
        "10.20.0.0/22, 10.20.0.0/22, 4",
        "172.16.5.0/24, 172.16.5.0/24, 4",
        "172.31.255.0/24, 172.31.255.0/24, 4",
        "169.254.10.0/24, 169.254.10.0/24, 4",
        "192.168.1.10/32, 192.168.1.10/32, 4",
        "fd00:0:0:1::/64, fd00:0:0:1::/64, 6",
        "FD12:3456:789A:1::/64, fd12:3456:789a:1::/64, 6",
        "fe80::/64, fe80::/64, 6"
    })
    void acceptsPrivateRanges(String input, String canonical, int version) {
        NetworkRange range = NetworkRange.parse(input);
        assertThat(range.cidr()).isEqualTo(canonical);
        assertThat(range.ipVersion()).isEqualTo(version);
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "8.8.8.0/24",          // public
        "100.64.0.0/24",       // CGNAT (RFC 6598): shared with other customers of the ISP
        "172.32.0.0/24",       // just outside 172.16.0.0/12
        "192.169.0.0/24",
        "2001:db8::/64",       // documentation / global IPv6
        "2a00:1450::/64"
    })
    void refusesPublicAndCarrierRanges(String input) {
        assertCode(input, "NETWORK_NOT_PRIVATE");
    }

    @ParameterizedTest
    @ValueSource(strings = {"10.0.0.0/8", "192.168.0.0/16", "10.0.0.0/21", "fd00::/48", "fd00::/56"})
    void refusesRangesLargerThanTheLimit(String input) {
        assertCode(input, "NETWORK_TOO_LARGE");
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "192.168.1.5/24",      // host bits set
        "192.168.1.0",         // no prefix
        "192.168.1.0/33",
        "192.168.1.0/-1",
        "192.168.001.0/24",    // leading zeros are ambiguous (octal in some parsers)
        "256.1.1.0/24",
        "localhost/24",        // names are never resolved
        "router.example.com/24",
        "fe80::1%eth0/64",     // zone ids not accepted
        "::ffff:192.168.1.0/120",
        "",
        "/24"
    })
    void refusesMalformedInput(String input) {
        assertCode(input, "INVALID_CIDR");
    }

    @Test
    void refusesNull() {
        assertCode(null, "INVALID_CIDR");
    }

    private static void assertCode(String input, String code) {
        assertThatThrownBy(() -> NetworkRange.parse(input))
                .isInstanceOf(ApiException.class)
                .satisfies(e -> assertThat(((ApiException) e).getCode()).isEqualTo(code));
    }
}

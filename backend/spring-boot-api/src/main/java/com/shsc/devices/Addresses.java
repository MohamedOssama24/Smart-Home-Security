package com.shsc.devices;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.HexFormat;
import java.util.Locale;
import java.util.Optional;

/**
 * Classification of the addresses of a device (M19, ADR-074): family, scope and, for IPv6, the
 * kind of interface identifier. An EUI-64 identifier embeds the MAC of the interface (RFC 4291
 * appendix A), a random one is a temporary/privacy or stable-opaque address (RFC 8981 / RFC 7217:
 * the two cannot be told apart from the network, so both are reported as RANDOM).
 */
public final class Addresses {

    public enum Scope { PRIVATE, PUBLIC, LINK_LOCAL, LOOPBACK, UNIQUE_LOCAL, GLOBAL, MULTICAST, OTHER }

    public enum InterfaceId { EUI64, RANDOM }

    /** Classification of one address; {@code interfaceId} and {@code eui64Mac} only for IPv6. */
    public record Info(String address, int family, Scope scope, InterfaceId interfaceId, String eui64Mac) {
        /** IPv6 address whose identifier changes over time: kept for a limited time. */
        public boolean ephemeral() {
            return family == 6 && interfaceId == InterfaceId.RANDOM && scope == Scope.GLOBAL;
        }
    }

    private Addresses() {
    }

    /** Classifies a literal IPv4/IPv6 address (never resolves names); empty when it is not a literal. */
    public static Optional<Info> classify(String literal) {
        if (literal == null || literal.isBlank() || !literal.matches("[0-9A-Fa-f:.]+")
                || !(literal.contains(":") || literal.matches("\\d{1,3}(\\.\\d{1,3}){3}"))) {
            return Optional.empty();
        }
        byte[] b;
        try {
            b = InetAddress.getByName(literal).getAddress();
        } catch (UnknownHostException e) {
            return Optional.empty();
        }
        if (b.length == 4) {
            return Optional.of(new Info(literal, 4, scope4(b), null, null));
        }
        Scope scope = scope6(b);
        if (scope == Scope.MULTICAST || scope == Scope.LOOPBACK || scope == Scope.OTHER) {
            return Optional.of(new Info(literal, 6, scope, null, null));
        }
        String mac = eui64Mac(b).orElse(null);
        return Optional.of(new Info(literal, 6, scope, mac != null ? InterfaceId.EUI64 : InterfaceId.RANDOM, mac));
    }

    /** MAC embedded in an IPv6 EUI-64 interface identifier (xx:xx:xx:ff:fe:xx:xx:xx, U/L bit inverted). */
    public static Optional<String> eui64Mac(String literal) {
        return classify(literal).map(Info::eui64Mac);
    }

    private static Optional<String> eui64Mac(byte[] b) {
        if ((b[11] & 0xff) != 0xff || (b[12] & 0xff) != 0xfe) {
            return Optional.empty();
        }
        byte[] mac = { (byte) (b[8] ^ 0x02), b[9], b[10], b[13], b[14], b[15] };
        if (allZero(mac)) {
            return Optional.empty();
        }
        return Optional.of(HexFormat.ofDelimiter(":").formatHex(mac).toLowerCase(Locale.ROOT));
    }

    private static Scope scope4(byte[] b) {
        int a = b[0] & 0xff;
        int c = b[1] & 0xff;
        if (a == 127) {
            return Scope.LOOPBACK;
        }
        if (a == 169 && c == 254) {
            return Scope.LINK_LOCAL;
        }
        if (a >= 224 && a <= 239) {
            return Scope.MULTICAST;
        }
        if (a == 10 || (a == 172 && c >= 16 && c <= 31) || (a == 192 && c == 168) || (a == 100 && c >= 64 && c <= 127)) {
            return Scope.PRIVATE;
        }
        if (a == 0 || a >= 240) {
            return Scope.OTHER;
        }
        return Scope.PUBLIC;
    }

    private static Scope scope6(byte[] b) {
        int a = b[0] & 0xff;
        if (a == 0xff) {
            return Scope.MULTICAST;
        }
        if (a == 0xfe && (b[1] & 0xc0) == 0x80) {
            return Scope.LINK_LOCAL;
        }
        if ((a & 0xfe) == 0xfc) {
            return Scope.UNIQUE_LOCAL;
        }
        if ((a & 0xe0) == 0x20) {
            return Scope.GLOBAL;
        }
        boolean zeroPrefix = true;
        for (int i = 0; i < 15; i++) {
            zeroPrefix &= b[i] == 0;
        }
        if (zeroPrefix && b[15] == 1) {
            return Scope.LOOPBACK;
        }
        return Scope.OTHER;
    }

    private static boolean allZero(byte[] v) {
        for (byte x : v) {
            if (x != 0) {
                return false;
            }
        }
        return true;
    }
}

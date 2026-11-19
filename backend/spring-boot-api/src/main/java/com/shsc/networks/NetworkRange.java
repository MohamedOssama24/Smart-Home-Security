package com.shsc.networks;

import java.math.BigInteger;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.List;
import java.util.regex.Pattern;

import com.shsc.shared.web.ApiException;

/**
 * A network range in CIDR notation that may be declared for a home. Only private and
 * link-local ranges are accepted (RFC 1918, 169.254.0.0/16, IPv6 ULA fc00::/7 and link-local
 * fe80::/10): public addresses and CGNAT (100.64.0.0/10) never. Size limit: at most 1024 IPv4
 * addresses (/22 or longer prefix), IPv6 /64 or longer. The database enforces the same rules.
 * <p>
 * Parsing never resolves names: only numeric literals are accepted.
 */
public record NetworkRange(InetAddress address, int prefixLength) {

    public static final int MIN_IPV4_PREFIX = 22;
    public static final int MIN_IPV6_PREFIX = 64;

    private static final Pattern IPV4 = Pattern.compile("^(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})\\.(\\d{1,3})$");
    private static final Pattern IPV6 = Pattern.compile("^[0-9A-Fa-f:]{2,39}$");

    private record Block(byte[] network, int prefix) {
    }

    private static final List<Block> PRIVATE_V4 = List.of(
            block(10, 0, 0, 0, 8), block(172, 16, 0, 0, 12), block(192, 168, 0, 0, 16), block(169, 254, 0, 0, 16));
    private static final List<Block> PRIVATE_V6 = List.of(
            new Block(v6Prefix(0xfc), 7), new Block(v6Prefix(0xfe, 0x80), 10));

    public static NetworkRange parse(String text) {
        if (text == null) {
            throw invalid();
        }
        String[] parts = text.trim().split("/", -1);
        if (parts.length != 2 || parts[1].isEmpty() || parts[1].length() > 3 || !parts[1].chars().allMatch(Character::isDigit)) {
            throw invalid();
        }
        InetAddress address = literal(parts[0]);
        int prefix = Integer.parseInt(parts[1]);
        int bits = address.getAddress().length * 8;
        if (prefix > bits) {
            throw invalid();
        }
        if (!hostBitsZero(address.getAddress(), prefix)) {
            throw ApiException.badRequest("INVALID_CIDR",
                    "The address must be the network address of the range (host bits set to zero).");
        }
        List<Block> allowed = bits == 32 ? PRIVATE_V4 : PRIVATE_V6;
        boolean isPrivate = allowed.stream()
                .anyMatch(b -> prefix >= b.prefix() && samePrefix(address.getAddress(), b.network(), b.prefix()));
        if (!isPrivate) {
            throw ApiException.badRequest("NETWORK_NOT_PRIVATE",
                    "Only private or link-local networks can be declared.");
        }
        int minimum = bits == 32 ? MIN_IPV4_PREFIX : MIN_IPV6_PREFIX;
        if (prefix < minimum) {
            throw ApiException.badRequest("NETWORK_TOO_LARGE", "The network is larger than the allowed size.");
        }
        return new NetworkRange(address, prefix);
    }

    /** Canonical CIDR text, e.g. {@code 192.168.1.0/24} or {@code fd00:1::/64}. */
    public String cidr() {
        String host = address.getHostAddress();
        if (address.getAddress().length == 16) {
            host = compressIpv6(address.getAddress());
        }
        return host + "/" + prefixLength;
    }

    public int ipVersion() {
        return address.getAddress().length == 4 ? 4 : 6;
    }

    /**
     * Whether {@code ip} (numeric literal, never resolved through DNS) belongs to this range.
     * Returns false for anything that is not a valid literal of the same family.
     */
    public boolean contains(String ip) {
        InetAddress candidate;
        try {
            candidate = literal(ip == null ? "" : ip.trim());
        } catch (ApiException notALiteral) {
            return false;
        }
        byte[] bytes = candidate.getAddress();
        return bytes.length == address.getAddress().length && samePrefix(bytes, address.getAddress(), prefixLength);
    }

    private static InetAddress literal(String text) {
        try {
            if (IPV4.matcher(text).matches()) {
                for (String octet : text.split("\\.")) {
                    if (Integer.parseInt(octet) > 255 || (octet.length() > 1 && octet.startsWith("0"))) {
                        throw invalid();
                    }
                }
                return InetAddress.getByName(text);
            }
            if (IPV6.matcher(text).matches() && text.contains(":")) {
                // a numeric IPv6 literal: InetAddress does not perform a lookup for it
                return InetAddress.getByName(text);
            }
        } catch (UnknownHostException e) {
            throw invalid();
        }
        throw invalid();
    }

    private static boolean hostBitsZero(byte[] address, int prefix) {
        BigInteger value = new BigInteger(1, address);
        int bits = address.length * 8;
        BigInteger hostMask = BigInteger.ONE.shiftLeft(bits - prefix).subtract(BigInteger.ONE);
        return value.and(hostMask).signum() == 0;
    }

    private static boolean samePrefix(byte[] address, byte[] network, int prefix) {
        int bits = address.length * 8;
        BigInteger a = new BigInteger(1, address).shiftRight(bits - prefix);
        BigInteger n = new BigInteger(1, network).shiftRight(bits - prefix);
        return a.equals(n);
    }

    private static Block block(int a, int b, int c, int d, int prefix) {
        return new Block(new byte[] {(byte) a, (byte) b, (byte) c, (byte) d}, prefix);
    }

    private static byte[] v6Prefix(int... leading) {
        byte[] bytes = new byte[16];
        for (int i = 0; i < leading.length; i++) {
            bytes[i] = (byte) leading[i];
        }
        return bytes;
    }

    private static String compressIpv6(byte[] bytes) {
        int[] groups = new int[8];
        for (int i = 0; i < 8; i++) {
            groups[i] = ((bytes[2 * i] & 0xff) << 8) | (bytes[2 * i + 1] & 0xff);
        }
        // longest run of zero groups (length >= 2) is replaced by "::" (RFC 5952)
        int bestStart = -1;
        int bestLength = 0;
        for (int i = 0; i < 8;) {
            if (groups[i] != 0) {
                i++;
                continue;
            }
            int start = i;
            while (i < 8 && groups[i] == 0) {
                i++;
            }
            if (i - start > bestLength) {
                bestStart = start;
                bestLength = i - start;
            }
        }
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (bestLength >= 2 && i == bestStart) {
                out.append("::");
                i += bestLength - 1;
                continue;
            }
            if (out.length() > 0 && out.charAt(out.length() - 1) != ':') {
                out.append(':');
            }
            out.append(Integer.toHexString(groups[i]));
        }
        return out.toString();
    }

    private static ApiException invalid() {
        return ApiException.badRequest("INVALID_CIDR", "The network must be written in CIDR notation, e.g. 192.168.1.0/24.");
    }
}

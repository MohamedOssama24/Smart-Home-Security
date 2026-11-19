package com.shsc.devices.fingerprint;

/**
 * One piece of evidence about a host: a named field (e.g. {@code mdns.service},
 * {@code hostname}, {@code oui}), its value and the source that produced it (the discovery
 * method, or {@code OUI}). Two signals are independent when their sources differ.
 */
public record Signal(String field, String value, String source) {
}

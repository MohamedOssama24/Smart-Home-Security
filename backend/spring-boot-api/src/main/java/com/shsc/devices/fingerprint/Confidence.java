package com.shsc.devices.fingerprint;

/** Confidence of a value (docs/07-DISCOVERY-FINGERPRINTING.md §3). */
public enum Confidence {
    LOW, MEDIUM, HIGH;

    /** One level lower (conflicting sources); LOW stays LOW. */
    public Confidence lower() {
        return this == HIGH ? MEDIUM : LOW;
    }

    public boolean atLeast(Confidence other) {
        return compareTo(other) >= 0;
    }
}

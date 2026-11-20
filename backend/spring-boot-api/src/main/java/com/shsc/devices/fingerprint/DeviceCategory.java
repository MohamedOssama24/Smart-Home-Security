package com.shsc.devices.fingerprint;

/** Device categories (docs/07-DISCOVERY-FINGERPRINTING.md §2.3); UNKNOWN_DEVICE when evidence is not enough. */
public enum DeviceCategory {
    ROUTER, IP_CAMERA, SMART_TV, SMARTPHONE, TABLET, LAPTOP, DESKTOP, PRINTER, NAS, SMART_PLUG, SMART_SPEAKER, IOT,
    VOIP_PHONE, NETWORK_DEVICE, SERVER, UNKNOWN_DEVICE
}

-- ADR-079: new device categories VOIP_PHONE (IP phones), NETWORK_DEVICE (firewall, switch,
-- access point) and SERVER. Same list for the automatic and the manual category.

ALTER TABLE devices DROP CONSTRAINT devices_detected_category_check;
ALTER TABLE devices DROP CONSTRAINT devices_manual_category_check;

ALTER TABLE devices ADD CONSTRAINT devices_detected_category_check
    CHECK (detected_category IN ('ROUTER', 'IP_CAMERA', 'SMART_TV', 'SMARTPHONE', 'TABLET', 'LAPTOP', 'DESKTOP',
                                 'PRINTER', 'NAS', 'SMART_PLUG', 'SMART_SPEAKER', 'IOT', 'VOIP_PHONE',
                                 'NETWORK_DEVICE', 'SERVER', 'UNKNOWN_DEVICE'));
ALTER TABLE devices ADD CONSTRAINT devices_manual_category_check
    CHECK (manual_category IN ('ROUTER', 'IP_CAMERA', 'SMART_TV', 'SMARTPHONE', 'TABLET', 'LAPTOP', 'DESKTOP',
                               'PRINTER', 'NAS', 'SMART_PLUG', 'SMART_SPEAKER', 'IOT', 'VOIP_PHONE',
                               'NETWORK_DEVICE', 'SERVER', 'UNKNOWN_DEVICE'));

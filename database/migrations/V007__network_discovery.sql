-- M7 - Network device discovery (docs/16-NETWORK-DISCOVERY.md).
--
-- * scan_observations accepts the new discovery methods. Each observation may carry the host
--   name the method learnt and a small JSON object of method-specific details (for example
--   the services announced over mDNS, the UPnP description, the port mappings declared by an
--   Internet gateway). What devices declare about themselves is stored as self-declared,
--   never as verified. Linking to a device inventory comes with fingerprinting (M8).

ALTER TABLE scan_observations DROP CONSTRAINT scan_observations_method_check;
ALTER TABLE scan_observations ADD CONSTRAINT scan_observations_method_check
    CHECK (method IN ('ARP', 'SELF', 'ICMP', 'MDNS', 'SSDP', 'UPNP_IGD', 'NETBIOS', 'RDNS', 'NDP', 'TR064', 'SNMP'));

ALTER TABLE scan_observations
    ADD COLUMN hostname text CHECK (length(hostname) BETWEEN 1 AND 255),
    ADD COLUMN details  jsonb CHECK (jsonb_typeof(details) = 'object' AND octet_length(details::text) <= 4096);

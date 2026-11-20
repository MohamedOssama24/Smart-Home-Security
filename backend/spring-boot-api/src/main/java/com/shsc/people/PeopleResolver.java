package com.shsc.people;

import java.time.Instant;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Service;

import com.shsc.integrations.HomeAssistantRepository.GatewayDevice;
import com.shsc.people.PeopleRepository.DeviceIdentity;
import com.shsc.people.PeopleRepository.DeviceName;
import com.shsc.people.PeopleRepository.Person;

/**
 * Automatic associations at the end of a scan (M24, ADR-081), in the transaction of the scan:
 * a person name found in a name announced by a device (PersonNames) becomes a PROBABLE
 * association, with the name as evidence. No traffic: only names already collected. A person
 * the user dismissed is never created again; a pair the user confirmed or rejected is kept.
 */
@Service
public class PeopleResolver {

    public static final String SOURCE_DEVICE_NAME = "DEVICE_NAME";
    public static final String SOURCE_HOME_ASSISTANT = "HOME_ASSISTANT";
    public static final String SOURCE_DIRECTORY = "DIRECTORY";
    public static final String SOURCE_FIREWALL = "FIREWALL";

    private final PeopleRepository people;

    public PeopleResolver(PeopleRepository people) {
        this.people = people;
    }

    /**
     * {@code gateway}: Home Assistant devices of the scan by lower-case MAC. The accounts the agent
     * saw on the addresses of the scan (Active Directory logons, Sophos authentications: ADR-083)
     * become PROBABLE associations of the device that had the address.
     */
    public void resolve(UUID homeId, UUID scanId, Map<String, GatewayDevice> gateway, Instant now) {
        for (DeviceName d : people.deviceNames(homeId)) {
            propose(homeId, d, d.name(), SOURCE_DEVICE_NAME, now);
            GatewayDevice ha = d.mac() == null ? null : gateway.get(d.mac().toLowerCase(Locale.ROOT));
            if (ha != null && ha.name() != null) {
                propose(homeId, d, ha.name(), SOURCE_HOME_ASSISTANT, now);
            }
        }
        for (DeviceIdentity i : people.identitiesOfScan(scanId)) {
            account(i.tenantId(), homeId, i.account(), i.source(), now)
                    .ifPresent(p -> people.propose(i.tenantId(), i.deviceId(), p, i.source(),
                            i.account() + " @ " + i.ip() + ", " + i.observedAt(), now));
        }
    }

    /**
     * The person of an account: the one created from the same account by either source, else the
     * person with the same name (e.g. created by the user), else a new one; empty when dismissed.
     */
    Optional<UUID> account(UUID tenantId, UUID homeId, String account, String origin, Instant now) {
        String key = account.toLowerCase(Locale.ROOT);
        Optional<Person> existing = people.byExternalKey(homeId, SOURCE_DIRECTORY, key)
                .or(() -> people.byExternalKey(homeId, SOURCE_FIREWALL, key))
                .or(() -> people.byName(homeId, account));
        if (existing.isEmpty()) {
            Optional<UUID> created = people.insertAutomatic(tenantId, homeId, account, origin, key, now);
            if (created.isPresent()) {
                return created;
            }
            existing = people.byName(homeId, account);
        }
        return existing.filter(p -> !p.dismissed()).map(Person::id);
    }

    private void propose(UUID homeId, DeviceName device, String name, String source, Instant now) {
        Optional<PersonNames.Found> found = PersonNames.find(name);
        if (found.isEmpty()) {
            return;
        }
        person(device.tenantId(), homeId, found.get().name(), source, now)
                .ifPresent(p -> people.propose(device.tenantId(), device.deviceId(), p, source,
                        found.get().evidence(), now));
    }

    /** The visible person with this name, created when missing; empty when the user dismissed it. */
    Optional<UUID> person(UUID tenantId, UUID homeId, String name, String origin, Instant now) {
        Optional<Person> existing = people.byName(homeId, name);
        if (existing.isEmpty()) {
            Optional<UUID> created = people.insertAutomatic(tenantId, homeId, name, origin, null, now);
            if (created.isPresent()) {
                return created;
            }
            existing = people.byName(homeId, name);
        }
        return existing.filter(p -> !p.dismissed()).map(Person::id);
    }
}

package com.shsc.people;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.devices.DeviceRepository;
import com.shsc.devices.DeviceRepository.Device;
import com.shsc.homes.HomeRepository;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.people.PeopleRepository.Assignment;
import com.shsc.people.PeopleRepository.Person;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;

/**
 * People of a home and their devices (M24, ADR-081): {@code person:read} to see them,
 * {@code person:manage} to change them (other tenants and homes outside the scopes: 404).
 * Every change by a user is audited; the audit never contains the name of the person.
 */
@Service
public class PeopleService {

    public record PersonView(Person person, List<Assignment> devices) {
    }

    static final int MAX_NAME = 100;

    private final PeopleRepository people;
    private final DeviceRepository devices;
    private final HomeRepository homes;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final Clock clock;

    public PeopleService(PeopleRepository people, DeviceRepository devices, HomeRepository homes, AccessPolicy access,
            AuditLog audit, Clock clock) {
        this.people = people;
        this.devices = devices;
        this.homes = homes;
        this.access = access;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public List<PersonView> list(UUID homeId) {
        homes.find(homeId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.PERSON_READ, homeId);
        Map<UUID, List<Assignment>> assignments = people.assignments(homeId);
        return people.ofHome(homeId).stream()
                .map(p -> new PersonView(p, assignments.getOrDefault(p.id(), List.of()))).toList();
    }

    /** A new person; a person the user deleted earlier with the same name comes back without its devices. */
    @Transactional
    public PersonView create(UUID homeId, String name, ClientInfo client) {
        homes.find(homeId).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.PERSON_MANAGE, homeId);
        String n = name(name);
        Instant now = clock.instant();
        Optional<Person> same = people.byName(homeId, n);
        UUID id;
        if (same.isPresent() && !same.get().dismissed()) {
            throw ApiException.conflict("PERSON_EXISTS", "A person with this name already exists.");
        } else if (same.isPresent()) {
            id = same.get().id();
            people.restore(id, now);
            people.update(id, n, null, now);
        } else {
            id = people.insert(user.tenantId(), homeId, n, "USER", null, null, user.userId(), now);
        }
        audit.record(AuditEvent.of(AuditAction.PERSON_CREATED).tenant(user.tenantId()).user(user.userId())
                .client(client).target("PERSON", id).detail("homeId", homeId).build());
        return view(people.lock(id).orElseThrow());
    }

    @Transactional
    public PersonView rename(UUID personId, String name, ClientInfo client) {
        Person p = visible(personId);
        AuthenticatedUser user = access.requireOnHome(Permissions.PERSON_MANAGE, p.homeId());
        String n = name(name);
        Optional<Person> same = people.byName(p.homeId(), n);
        if (same.isPresent() && !same.get().id().equals(personId)) {
            throw ApiException.conflict("PERSON_EXISTS", "A person with this name already exists.");
        }
        if (!n.equals(p.name())) {
            people.update(personId, n, p.userId(), clock.instant());
            audit.record(AuditEvent.of(AuditAction.PERSON_RENAMED).tenant(p.tenantId()).user(user.userId())
                    .client(client).target("PERSON", personId).detail("homeId", p.homeId()).build());
        }
        return view(people.lock(personId).orElseThrow());
    }

    /**
     * Deletes the person and all its associations. A person created by an automatic source is
     * kept only as a hidden name, so that the next scans do not create it again.
     */
    @Transactional
    public void delete(UUID personId, ClientInfo client) {
        Person p = visible(personId);
        AuthenticatedUser user = access.requireOnHome(Permissions.PERSON_MANAGE, p.homeId());
        if ("USER".equals(p.origin())) {
            people.delete(personId);
        } else {
            people.dismiss(personId, clock.instant());
        }
        audit.record(AuditEvent.of(AuditAction.PERSON_DELETED).tenant(p.tenantId()).user(user.userId())
                .client(client).target("PERSON", personId).detail("homeId", p.homeId()).build());
    }

    /** Assigns the device to the person, or confirms a probable association. */
    @Transactional
    public PersonView assign(UUID deviceId, UUID personId, ClientInfo client) {
        return decide(deviceId, personId, "CONFIRMED", AuditAction.DEVICE_PERSON_ASSIGNED, client);
    }

    /** Removes the association (confirmed or probable): automatic sources will not propose it again. */
    @Transactional
    public PersonView unassign(UUID deviceId, UUID personId, ClientInfo client) {
        return decide(deviceId, personId, "REJECTED", AuditAction.DEVICE_PERSON_REMOVED, client);
    }

    private PersonView decide(UUID deviceId, UUID personId, String status, AuditAction action, ClientInfo client) {
        Device device = devices.find(deviceId).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.PERSON_MANAGE, device.homeId());
        Person p = people.lock(personId).filter(x -> !x.dismissed() && x.homeId().equals(device.homeId()))
                .orElseThrow(ApiException::notFound);
        if (!people.status(deviceId, personId).map(status::equals).orElse(false)) {
            people.decide(device.tenantId(), deviceId, personId, status, user.userId(), clock.instant());
            audit.record(AuditEvent.of(action).tenant(device.tenantId()).user(user.userId()).client(client)
                    .target("DEVICE", deviceId).detail("homeId", device.homeId()).detail("personId", personId)
                    .build());
        }
        return view(p);
    }

    private Person visible(UUID personId) {
        Person p = people.lock(personId).filter(x -> !x.dismissed()).orElseThrow(ApiException::notFound);
        homes.find(p.homeId()).orElseThrow(ApiException::notFound);
        return p;
    }

    private PersonView view(Person p) {
        return new PersonView(p, people.assignments(p.homeId()).getOrDefault(p.id(), List.of()));
    }

    private static String name(String name) {
        String v = name == null ? null : name.replaceAll("\\p{Cntrl}", "").strip();
        if (v == null || v.isEmpty()) {
            throw ApiException.badRequest("INVALID_NAME", "Empty name.");
        }
        return v.length() <= MAX_NAME ? v : v.substring(0, MAX_NAME);
    }
}

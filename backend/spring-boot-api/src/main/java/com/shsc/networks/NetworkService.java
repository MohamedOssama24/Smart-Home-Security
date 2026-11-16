package com.shsc.networks;

import java.time.Clock;
import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.dao.DuplicateKeyException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import com.shsc.audit.AuditAction;
import com.shsc.audit.AuditEvent;
import com.shsc.audit.AuditLog;
import com.shsc.homes.HomeRepository;
import com.shsc.identity.access.AccessPolicy;
import com.shsc.identity.access.AuthenticatedUser;
import com.shsc.identity.access.Permissions;
import com.shsc.networks.NetworkRepository.Kind;
import com.shsc.networks.NetworkRepository.Network;
import com.shsc.shared.web.ApiException;
import com.shsc.shared.web.ClientInfo;
import com.shsc.tenancy.PlanLimits;
import com.shsc.tenancy.PlanLimits.Resource;

/**
 * Networks of a home. In this milestone networks are declared by the user (source MANUAL);
 * the agent will propose the networks it is connected to in a later milestone and will in
 * any case refuse targets outside its directly connected subnets.
 * <p>
 * A network can be scanned only while it has an active authorization: the user explicitly
 * declares (attestation, versioned text shown by the UI) to own the network or to be
 * authorized by its owner. Authorizations are kept as history and audited. Declaring or
 * authorizing a network never triggers a scan: there is no scanning in this milestone.
 */
@Service
public class NetworkService {

    /** Version of the attestation text the UI shows (i18n key {@code networks.attestation.v1}). */
    public static final String ATTESTATION_VERSION = "1";

    private final NetworkRepository networks;
    private final HomeRepository homes;
    private final PlanLimits limits;
    private final AccessPolicy access;
    private final AuditLog audit;
    private final Clock clock;

    public NetworkService(NetworkRepository networks, HomeRepository homes, PlanLimits limits, AccessPolicy access,
            AuditLog audit, Clock clock) {
        this.networks = networks;
        this.homes = homes;
        this.limits = limits;
        this.access = access;
        this.audit = audit;
        this.clock = clock;
    }

    @Transactional(readOnly = true)
    public List<Network> list(UUID homeId) {
        homes.find(homeId).orElseThrow(ApiException::notFound);
        access.requireOnHome(Permissions.HOME_READ, homeId);
        return networks.forHome(homeId);
    }

    @Transactional
    public Network create(UUID homeId, String name, String cidrText, Kind kind, ClientInfo client) {
        // the home lock serializes concurrent declarations (overlap check + plan limit)
        homes.lock(homeId).orElseThrow(ApiException::notFound);
        AuthenticatedUser user = access.requireOnHome(Permissions.NETWORK_MANAGE, homeId);
        NetworkRange range = NetworkRange.parse(cidrText);
        List<String> overlapping = networks.overlapping(homeId, range.cidr());
        if (!overlapping.isEmpty()) {
            throw ApiException.conflict("NETWORK_OVERLAP", "The network overlaps another network of this home.");
        }
        limits.requireCapacity(Resource.NETWORKS_PER_HOME, homeId);
        UUID id = networks.insert(user.tenantId(), homeId, name.trim(), range.cidr(), kind == null ? Kind.UNKNOWN : kind,
                user.userId(), clock.instant());
        audit.record(AuditEvent.of(AuditAction.NETWORK_CREATED).tenant(user.tenantId()).user(user.userId())
                .target("NETWORK", id).client(client).detail("homeId", homeId).detail("cidr", range.cidr()).build());
        return networks.find(id).orElseThrow();
    }

    @Transactional
    public Network update(UUID networkId, String name, Kind kind, ClientInfo client) {
        Network network = lockedNetwork(networkId);
        AuthenticatedUser user = access.requireOnHome(Permissions.NETWORK_MANAGE, network.homeId());
        networks.update(networkId, name.trim(), kind == null ? Kind.UNKNOWN : kind, clock.instant());
        audit.record(AuditEvent.of(AuditAction.NETWORK_UPDATED).tenant(user.tenantId()).user(user.userId())
                .target("NETWORK", networkId).client(client).detail("homeId", network.homeId()).build());
        return networks.find(networkId).orElseThrow();
    }

    @Transactional
    public void delete(UUID networkId, ClientInfo client) {
        Network network = lockedNetwork(networkId);
        AuthenticatedUser user = access.requireOnHome(Permissions.NETWORK_MANAGE, network.homeId());
        networks.delete(networkId);
        audit.record(AuditEvent.of(AuditAction.NETWORK_DELETED).tenant(user.tenantId()).user(user.userId())
                .target("NETWORK", networkId).client(client).detail("homeId", network.homeId())
                .detail("cidr", network.cidr()).detail("wasAuthorized", network.authorization() != null).build());
    }

    /** Records the user's attestation that the network may be scanned. */
    @Transactional
    public Network authorize(UUID networkId, boolean attestation, String attestationVersion, ClientInfo client) {
        Network network = lockedNetwork(networkId);
        AuthenticatedUser user = access.requireOnHome(Permissions.NETWORK_AUTHORIZE, network.homeId());
        if (!attestation) {
            throw ApiException.badRequest("ATTESTATION_REQUIRED",
                    "Confirm that you own this network or are authorized by its owner.");
        }
        if (!ATTESTATION_VERSION.equals(attestationVersion)) {
            throw ApiException.badRequest("ATTESTATION_OUTDATED", "The attestation text has changed: reload the page.");
        }
        if (network.authorization() != null) {
            throw ApiException.conflict("NETWORK_ALREADY_AUTHORIZED", "The network is already authorized.");
        }
        Instant now = clock.instant();
        try {
            networks.authorize(user.tenantId(), networkId, user.userId(), ATTESTATION_VERSION, now);
        } catch (DuplicateKeyException race) {
            throw ApiException.conflict("NETWORK_ALREADY_AUTHORIZED", "The network is already authorized.");
        }
        audit.record(AuditEvent.of(AuditAction.NETWORK_AUTHORIZED).tenant(user.tenantId()).user(user.userId())
                .target("NETWORK", networkId).client(client).detail("homeId", network.homeId())
                .detail("cidr", network.cidr()).detail("attestationVersion", ATTESTATION_VERSION).build());
        return networks.find(networkId).orElseThrow();
    }

    @Transactional
    public Network revokeAuthorization(UUID networkId, ClientInfo client) {
        Network network = lockedNetwork(networkId);
        AuthenticatedUser user = access.requireOnHome(Permissions.NETWORK_AUTHORIZE, network.homeId());
        if (!networks.revokeAuthorization(networkId, user.userId(), clock.instant())) {
            throw ApiException.conflict("NETWORK_NOT_AUTHORIZED", "The network is not authorized.");
        }
        audit.record(AuditEvent.of(AuditAction.NETWORK_AUTHORIZATION_REVOKED).tenant(user.tenantId())
                .user(user.userId()).target("NETWORK", networkId).client(client).detail("homeId", network.homeId())
                .detail("cidr", network.cidr()).build());
        return networks.find(networkId).orElseThrow();
    }

    /** Finds the network and locks its home (404 for unknown ids and for other tenants). */
    private Network lockedNetwork(UUID networkId) {
        Network network = networks.find(networkId).orElseThrow(ApiException::notFound);
        homes.lock(network.homeId()).orElseThrow(ApiException::notFound);
        return networks.find(networkId).orElseThrow(ApiException::notFound);
    }
}

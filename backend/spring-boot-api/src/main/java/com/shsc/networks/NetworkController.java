package com.shsc.networks;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.PutMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestController;

import com.shsc.networks.NetworkRepository.Authorization;
import com.shsc.networks.NetworkRepository.Kind;
import com.shsc.networks.NetworkRepository.Network;
import com.shsc.shared.web.ClientInfo;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Networks of a home and their authorization for (future, manual) scans. */
@RestController
public class NetworkController {

    public record CreateNetworkRequest(@NotBlank @Size(max = 100) String name, @NotBlank @Size(max = 64) String cidr,
            Kind kind) {
    }

    public record UpdateNetworkRequest(@NotBlank @Size(max = 100) String name, Kind kind) {
    }

    public record AuthorizeRequest(boolean attestation, @Size(max = 4) String attestationVersion) {
    }

    public record AuthorizationResponse(UUID authorizedBy, Instant authorizedAt, String attestationVersion) {
        static AuthorizationResponse of(Authorization a) {
            return a == null ? null : new AuthorizationResponse(a.authorizedBy(), a.authorizedAt(), a.attestationVersion());
        }
    }

    public record NetworkResponse(UUID id, UUID homeId, String name, String cidr, int ipVersion, Kind kind,
            String source, boolean authorized, AuthorizationResponse authorization, Instant createdAt,
            Instant updatedAt) {
        static NetworkResponse of(Network n) {
            return new NetworkResponse(n.id(), n.homeId(), n.name(), n.cidr(), n.ipVersion(), n.kind(), n.source(),
                    n.authorization() != null, AuthorizationResponse.of(n.authorization()), n.createdAt(),
                    n.updatedAt());
        }
    }

    private final NetworkService networks;

    public NetworkController(NetworkService networks) {
        this.networks = networks;
    }

    @GetMapping("/api/v1/homes/{homeId}/networks")
    public List<NetworkResponse> list(@PathVariable UUID homeId) {
        return networks.list(homeId).stream().map(NetworkResponse::of).toList();
    }

    @PostMapping("/api/v1/homes/{homeId}/networks")
    @ResponseStatus(HttpStatus.CREATED)
    public NetworkResponse create(@PathVariable UUID homeId, @Valid @RequestBody CreateNetworkRequest request,
            HttpServletRequest http) {
        return NetworkResponse.of(networks.create(homeId, request.name(), request.cidr(), request.kind(),
                ClientInfo.from(http)));
    }

    @PutMapping("/api/v1/networks/{networkId}")
    public NetworkResponse update(@PathVariable UUID networkId, @Valid @RequestBody UpdateNetworkRequest request,
            HttpServletRequest http) {
        return NetworkResponse.of(networks.update(networkId, request.name(), request.kind(), ClientInfo.from(http)));
    }

    @DeleteMapping("/api/v1/networks/{networkId}")
    @ResponseStatus(HttpStatus.NO_CONTENT)
    public void delete(@PathVariable UUID networkId, HttpServletRequest http) {
        networks.delete(networkId, ClientInfo.from(http));
    }

    @PostMapping("/api/v1/networks/{networkId}/authorization")
    public NetworkResponse authorize(@PathVariable UUID networkId, @Valid @RequestBody AuthorizeRequest request,
            HttpServletRequest http) {
        return NetworkResponse.of(networks.authorize(networkId, request.attestation(), request.attestationVersion(),
                ClientInfo.from(http)));
    }

    @DeleteMapping("/api/v1/networks/{networkId}/authorization")
    public NetworkResponse revokeAuthorization(@PathVariable UUID networkId, HttpServletRequest http) {
        return NetworkResponse.of(networks.revokeAuthorization(networkId, ClientInfo.from(http)));
    }
}

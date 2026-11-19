package com.shsc.findings;

import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Component;

import tools.jackson.databind.json.JsonMapper;

/**
 * Copy of the agent's port lists (agent/go-security-agent/internal/portscan/portlists.json,
 * kept identical by a test). A finding about a port is RESOLVED only when the scan really
 * probed that port: same list version as the agent and the port in the profile's list.
 */
@Component
public class PortLists {

    static final String RESOURCE = "findings/portlists.json";

    record Profile(List<Integer> tcp, List<Integer> udp) {
    }

    record ListsFile(String version, Map<String, Profile> profiles, Map<String, String> services) {
    }

    private final String version;
    private final Map<String, Set<String>> ports;

    @Autowired
    public PortLists(JsonMapper json) {
        this(load(json));
    }

    PortLists(ListsFile file) {
        if (file.version() == null || file.profiles() == null || file.profiles().isEmpty()) {
            throw new IllegalStateException("port lists version or profiles missing");
        }
        this.version = file.version();
        this.ports = file.profiles().entrySet().stream().collect(Collectors.toUnmodifiableMap(Map.Entry::getKey,
                e -> java.util.stream.Stream.concat(
                        e.getValue().tcp().stream().map(p -> "TCP/" + p),
                        e.getValue().udp().stream().map(p -> "UDP/" + p)).collect(Collectors.toUnmodifiableSet())));
    }

    private static ListsFile load(JsonMapper json) {
        try (InputStream in = new ClassPathResource(RESOURCE).getInputStream()) {
            return json.readValue(in, ListsFile.class);
        } catch (IOException e) {
            throw new UncheckedIOException("cannot read " + RESOURCE, e);
        }
    }

    public String version() {
        return version;
    }

    /** Whether the profile's list (this version) contains the port. */
    public boolean contains(String profile, String protocol, int port) {
        Set<String> list = ports.get(profile);
        return list != null && list.contains(protocol + "/" + port);
    }
}

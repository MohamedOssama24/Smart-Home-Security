package com.shsc.devices.oui;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.transaction.support.TransactionTemplate;

import com.shsc.identity.access.RoleAssignment.ScopeType;
import com.shsc.shared.web.ApiException;
import com.shsc.support.Fixtures;
import com.shsc.support.IntegrationTest;
import com.shsc.support.TestAccounts.Account;
import com.sun.net.httpserver.HttpServer;

/**
 * IEEE registry synchronization against a local HTTP server serving [MOCK] files: nothing
 * leaves this machine. The registries are replaced only when every file was read; the
 * endpoints are reserved to platform administrators.
 */
class OuiSyncTest extends IntegrationTest {

    @Autowired
    private OuiSyncService service;

    @Autowired
    private OuiRepository repository;

    @Autowired
    private TransactionTemplate tx;

    @Autowired
    private Fixtures fixtures;

    private static final String MAL = """
            Registry,Assignment,Organization Name,Organization Address
            MA-L,7C1C4E,"MOCK Sync Maker, Inc.",Somewhere
            MA-L,7C1C4F,MOCK Sync Other,Somewhere
            """;
    private static final String MAS = """
            Registry,Assignment,Organization Name,Organization Address
            MA-S,7C1C4E123,MOCK Sync Small,Somewhere
            IAB,7C1C4E124,MOCK Ignored,Somewhere
            """;

    private static HttpServer server() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), 0), 0);
        Map<String, String> files = Map.of("/mal.csv", MAL, "/mas.csv", MAS, "/empty.csv",
                "Registry,Assignment,Organization Name,Organization Address\n");
        server.createContext("/", exchange -> {
            String body = files.get(exchange.getRequestURI().getPath());
            byte[] bytes = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
            exchange.sendResponseHeaders(body == null ? 404 : 200, bytes.length == 0 ? -1 : bytes.length);
            try (OutputStream out = exchange.getResponseBody()) {
                out.write(bytes);
            }
        });
        server.start();
        return server;
    }

    @Test
    void registriesAreReplacedOnlyWhenEveryFileWasRead() throws Exception {
        HttpServer server = server();
        try {
            String base = "http://127.0.0.1:" + server.getAddress().getPort();
            OuiSyncService.SyncResult result = service.sync(List.of(URI.create(base + "/mal.csv"),
                    URI.create(base + "/mas.csv")));
            assertThat(result.entries()).containsEntry("MA-L", 2).containsEntry("MA-S", 1);
            assertThat(result.skipped()).isEqualTo(1);
            assertThat(lookup("7c:1c:4e:12:34:56")).contains("MOCK Sync Small"); // longest prefix wins
            assertThat(lookup("7c:1c:4e:00:00:01")).contains("MOCK Sync Maker, Inc.");

            // one file missing or empty: refused, nothing replaced
            assertThatThrownBy(() -> service.sync(List.of(URI.create(base + "/mal.csv"),
                    URI.create(base + "/missing.csv"))))
                    .isInstanceOfSatisfying(ApiException.class,
                            e -> assertThat(e.getCode()).isEqualTo("OUI_SOURCE_UNAVAILABLE"));
            assertThatThrownBy(() -> service.sync(List.of(URI.create(base + "/empty.csv"))))
                    .isInstanceOfSatisfying(ApiException.class,
                            e -> assertThat(e.getCode()).isEqualTo("OUI_SOURCE_EMPTY"));
            // plain HTTP towards another host is never used (no connection is attempted)
            assertThatThrownBy(() -> service.sync(List.of(URI.create("http://192.0.2.1/oui.csv"))))
                    .isInstanceOfSatisfying(ApiException.class,
                            e -> assertThat(e.getCode()).isEqualTo("OUI_SOURCE_NOT_ALLOWED"));
            assertThat(lookup("7c:1c:4e:12:34:56")).contains("MOCK Sync Small");
        } finally {
            server.stop(0);
        }
    }

    @Test
    void onlyPlatformAdministratorsSeeOrStartTheSynchronization() {
        Account admin = accounts().business("MOCK Oui Srl");
        assertThat(admin.api().get("/api/v1/platform/oui").status()).isEqualTo(403);
        assertThat(admin.api().post("/api/v1/platform/oui/sync", null).status()).isEqualTo(403);
        Account platform = fixtures.addUser(accounts(), client(), admin, "SUPER_ADMIN", ScopeType.PLATFORM, null);
        // status only: a real synchronization would download from the configured IEEE sources
        assertThat(platform.api().get("/api/v1/platform/oui").status()).isEqualTo(200);
    }

    private java.util.Optional<String> lookup(String mac) {
        return tx.execute(s -> repository.organizationOf(mac));
    }
}

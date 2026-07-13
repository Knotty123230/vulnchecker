package com.vulncheck;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class NexusComponentVersionRepositoryTest {

    private HttpServer server;

    @AfterEach
    void stopServer() {
        if (server != null) {
            server.stop(0);
        }
    }

    @Test
    void validatesMavenRepositoryAndReadsAllSearchPagesWithPomAssets() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/service/rest/v1/repositories/releases", exchange -> json(exchange, 200,
                "{\"name\":\"releases\",\"format\":\"maven2\",\"type\":\"hosted\"}"));
        server.createContext("/service/rest/v1/search", exchange -> {
            boolean secondPage = exchange.getRequestURI().getQuery().contains("continuationToken=next");
            json(exchange, 200, secondPage ? page("1.2.0", null, true) : page("1.1.0", "next", true));
        });
        server.start();

        NexusComponentVersionRepository repository = new NexusComponentVersionRepository(configuration("releases"));

        assertEquals(
                List.of("1.1.0", "1.2.0"),
                repository.findVersions(new ComponentCoordinate("com.example", "library", "1.0.0"))
        );
    }

    @Test
    void rejectsRepositoryWithWrongFormat() throws IOException {
        server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.createContext("/service/rest/v1/repositories/npm", exchange ->
                json(exchange, 200, "{\"name\":\"npm\",\"format\":\"npm\"}"));
        server.start();

        NexusComponentVersionRepository repository = new NexusComponentVersionRepository(configuration("npm"));

        assertThrows(VersionRepositoryException.class, () -> repository.findVersions(
                new ComponentCoordinate("com.example", "library", "1.0.0")
        ));
    }

    private NexusRepositoryConfiguration configuration(String repository) {
        return new NexusRepositoryConfiguration(
                "http://127.0.0.1:" + server.getAddress().getPort(),
                repository,
                null,
                null,
                null,
                Duration.ofSeconds(2)
        );
    }

    private String page(String version, String continuationToken, boolean pom) {
        String token = continuationToken == null ? "null" : "\"" + continuationToken + "\"";
        String asset = pom ? "com/example/library/" + version + "/library-" + version + ".pom" : "library.jar";
        return "{\"items\":[{\"format\":\"maven2\",\"version\":\"" + version
                + "\",\"assets\":[{\"path\":\"" + asset + "\"}]}],\"continuationToken\":" + token + "}";
    }

    private void json(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (var output = exchange.getResponseBody()) {
            output.write(bytes);
        }
    }
}

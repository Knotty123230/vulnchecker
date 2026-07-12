package com.vulncheck;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Objects;


final class SonatypeClient {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration POLL_INTERVAL = Duration.ofMillis(250);
    private  final Duration scanTimeout;

    private final String apiKey;
    private final String username;
    private final String password;
    private final String baseUrl;
    private  final HttpClient httpClient;

    SonatypeClient(SonatypeCredentials sonatypeCredentials) {
        this.apiKey = sonatypeCredentials.apiKey();
        this.username = sonatypeCredentials.username();
        this.password = sonatypeCredentials.password();
        this.baseUrl = Objects.requireNonNull(sonatypeCredentials.baseUrl(), "sonatypeUrl must not be null");
        this.scanTimeout = Duration.parse(sonatypeCredentials.scanTimeout() == null ? "PT30S" : sonatypeCredentials.scanTimeout());
        this.httpClient = HttpClient.newBuilder().connectTimeout(Duration.parse(sonatypeCredentials.requestTimeout() == null ? "PT30S" : sonatypeCredentials.requestTimeout())).build();
    }

    JsonNode getRemediation(
            String applicationId,
            DependencyNode dependency
    ) {
        Objects.requireNonNull(dependency, "dependency must not be null");

        String stage = "develop";

        String path = "/api/v2/components/remediation/application/"
                + applicationId
                + "?stageId=" + encode(stage)
                + "&includeParentRemediation=" + true;

        Map<String, Object> body = Map.of(
                "packageUrl", dependency.toPkg("maven") + "?type=jar"
        );

        try {
            return send(
                    "POST",
                    path,
                    OBJECT_MAPPER.writeValueAsString(body)
            );
        } catch (JsonProcessingException e) {
            throw new IllegalStateException(
                    "Unable to serialize Sonatype remediation request",
                    e
            );
        }
    }


    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    String resolveInternalId(String publicId) {
        Objects.requireNonNull(publicId, "publicId must not be null");
        JsonNode response = send("GET",
                "/api/v2/applications?publicId=" + encode(publicId), null);
        JsonNode applications = response.path("applications");
        if (!applications.isArray() || applications.isEmpty()) {
            throw new IllegalStateException(
                    "Application with publicId '" + publicId + "' not found in Sonatype IQ");
        }
        String internalId = applications.get(0).path("id").asText(null);
        if (isBlank(internalId)) {
            throw new IllegalStateException(
                    "Sonatype IQ returned an application without an internal ID for publicId '" + publicId + "'");
        }
        return internalId;
    }

    /**
     * Fetches all applications from Sonatype IQ.
     * Returns a list of [publicId, name] pairs.
     */
    List<String[]> listApplications() {
        JsonNode response = send("GET", "/api/v2/applications", null);
        JsonNode applications = response.path("applications");
        if (!applications.isArray()) {
            return List.of();
        }
        List<String[]> result = new java.util.ArrayList<>();
        for (JsonNode app : applications) {
            String publicId = app.path("publicId").asText("");
            String name = app.path("name").asText("");
            result.add(new String[]{publicId, name});
        }
        return result;
    }

    JsonNode scan(String applicationId, Map<String, Object> bom) {
        try {
            JsonNode submittedScan = send("POST",
                    "/api/v2/scan/applications/" + applicationId + "/sources/cyclonedx?stageId=build",
                    OBJECT_MAPPER.writeValueAsString(bom));
            JsonNode scanResult = waitForScan(requiredText(submittedScan, "statusUrl", "Sonatype did not return a scan status URL"));
            if (scanResult.path("isError").asBoolean(false)) {
                throw new IllegalStateException("Sonatype scan failed: " + scanResult.path("errorMessage").asText("unknown error"));
            }
            return send("GET", requiredText(scanResult, "reportDataUrl", "Sonatype did not return a report data URL"), null);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Unable to serialize the Sonatype scan request", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for Sonatype scan results", e);
        }
    }

    private JsonNode waitForScan(String statusUrl) throws InterruptedException {
        long deadline = System.nanoTime() + scanTimeout.toNanos();
        while (System.nanoTime() < deadline) {
            try {
                return send("GET", statusUrl, null);
            } catch (SonatypeHttpException e) {
                if (e.statusCode != 404) {
                    throw e;
                }
                Thread.sleep(POLL_INTERVAL);
            }
        }
        throw new IllegalStateException("Timed out waiting for Sonatype scan results");
    }

    private JsonNode send(String method, String path, String body) {
        try {
            HttpRequest.Builder request = HttpRequest.newBuilder(resolve(path))
                    .timeout(REQUEST_TIMEOUT)
                    .header("Accept", "application/json")
                    .header("X-Api-Key", apiKey == null ? "" : apiKey);
            if (!isBlank(username) || !isBlank(password)) {
                String credentials = Objects.toString(username, "") + ":" + Objects.toString(password, "");
                request.header("Authorization", "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8)));
            }
            if (body == null) {
                request.method(method, HttpRequest.BodyPublishers.noBody());
            } else {
                request.header("Content-Type", "application/json")
                        .method(method, HttpRequest.BodyPublishers.ofString(body));
            }

            HttpResponse<String> response = httpClient.send(request.build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new SonatypeHttpException(response.statusCode(), response.body());
            }
            return OBJECT_MAPPER.readTree(response.body());
        } catch (IOException e) {
            throw new IllegalStateException("Sonatype request failed", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while calling Sonatype", e);
        }
    }

    private URI resolve(String path) {
        URI uri = URI.create(path);
        if (uri.isAbsolute()) {
            return uri;
        }
        return URI.create(baseUrl.replaceAll("/+$", "") + "/" + path.replaceFirst("^/+", ""));
    }

    private String requiredText(JsonNode node, String field, String message) {
        String value = node.path(field).asText();
        if (isBlank(value)) {
            throw new IllegalStateException(message);
        }
        return value;
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

    private static final class SonatypeHttpException extends RuntimeException {
        private final int statusCode;

        private SonatypeHttpException(int statusCode, String responseBody) {
            super("Sonatype request failed with HTTP " + statusCode + ": " + responseBody);
            this.statusCode = statusCode;
        }
    }
}

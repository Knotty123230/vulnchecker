package com.vulncheck;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

public class SonatypeVulnerabilitiesScanner implements VulnerabilitiesScanner {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Duration REQUEST_TIMEOUT = Duration.ofSeconds(30);
    private static final Duration POLL_INTERVAL = Duration.ofMillis(250);
    private static final Duration SCAN_TIMEOUT = Duration.ofSeconds(30);

    private final String sonatypeApiKey;
    private final String sonatypeUsername;
    private final String sonatypePassword;
    private final String sonatypeUrl;
    private final HttpClient httpClient;

    public SonatypeVulnerabilitiesScanner(String sonatypeApiKey, String sonatypeUsername, String sonatypePassword, String sonatypeUrl) {
        this.sonatypeApiKey = sonatypeApiKey;
        this.sonatypeUsername = sonatypeUsername;
        this.sonatypePassword = sonatypePassword;
        this.sonatypeUrl = sonatypeUrl;
        this.httpClient = HttpClient.newBuilder().connectTimeout(REQUEST_TIMEOUT).build();
    }

    @Override
    public List<Vulnerability> scanDependencies(int projectId, DependencyNode dependencyNode) {
        Objects.requireNonNull(dependencyNode, "dependencyNode must not be null");

        try {
            JsonNode submittedScan = send("POST",
                    "/api/v2/scan/applications/" + projectId + "/sources/cyclonedx?stageId=build",
                    OBJECT_MAPPER.writeValueAsString(toCycloneDxBom(dependencyNode)));
            String statusUrl = requiredText(submittedScan, "statusUrl", "Sonatype did not return a scan status URL");
            JsonNode scanResult = waitForScan(statusUrl);

            if (scanResult.path("isError").asBoolean(false)) {
                throw new IllegalStateException("Sonatype scan failed: " + scanResult.path("errorMessage").asText("unknown error"));
            }

            String reportDataUrl = requiredText(scanResult, "reportDataUrl", "Sonatype did not return a report data URL");
            return toVulnerabilities(send("GET", reportDataUrl, null));
        } catch (IOException e) {
            throw new IllegalStateException("Unable to serialize the Sonatype scan request", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Interrupted while waiting for Sonatype scan results", e);
        }
    }

    private Map<String, Object> toCycloneDxBom(DependencyNode root) {
        Map<String, DependencyNode> dependencies = new LinkedHashMap<>();
        collectDependencies(root, dependencies);

        List<Map<String, String>> components = dependencies.values().stream()
                .map(this::toComponent)
                .toList();
        List<Map<String, Object>> relationships = dependencies.values().stream()
                .map(this::toDependencyRelationship)
                .toList();

        return Map.of(
                "bomFormat", "CycloneDX",
                "specVersion", "1.5",
                "version", 1,
                "components", components,
                "dependencies", relationships
        );
    }

    private void collectDependencies(DependencyNode node, Map<String, DependencyNode> dependencies) {
        if (node == null || dependencies.putIfAbsent(packageUrl(node), node) != null || node.children() == null) {
            return;
        }
        node.children().forEach(child -> collectDependencies(child, dependencies));
    }

    private Map<String, String> toComponent(DependencyNode node) {
        String packageUrl = packageUrl(node);
        return Map.of(
                "type", "library",
                "bom-ref", packageUrl,
                "group", node.groupId(),
                "name", node.artifactId(),
                "version", node.version(),
                "purl", packageUrl
        );
    }

    private Map<String, Object> toDependencyRelationship(DependencyNode node) {
        List<String> children = node.children() == null ? List.of() : node.children().stream()
                .filter(Objects::nonNull)
                .map(this::packageUrl)
                .distinct()
                .toList();
        return Map.of("ref", packageUrl(node), "dependsOn", children);
    }

    private String packageUrl(DependencyNode node) {
        if (isBlank(node.groupId()) || isBlank(node.artifactId()) || isBlank(node.version())) {
            throw new IllegalArgumentException("Every dependency must have groupId, artifactId, and version");
        }
        return "pkg:maven/%s/%s@%s?type=jar".formatted(node.groupId(), node.artifactId(), node.version());
    }

    private JsonNode waitForScan(String statusUrl) throws InterruptedException {
        long deadline = System.nanoTime() + SCAN_TIMEOUT.toNanos();
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
                    .header("X-Api-Key", sonatypeApiKey == null ? "" : sonatypeApiKey);
            if (!isBlank(sonatypeUsername) || !isBlank(sonatypePassword)) {
                String credentials = (Objects.toString(sonatypeUsername, "") + ":" + Objects.toString(sonatypePassword, ""));
                request.header("Authorization", "Basic " + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8)));
            }
            if (body != null) {
                request.header("Content-Type", "application/json")
                        .method(method, HttpRequest.BodyPublishers.ofString(body));
            } else {
                request.method(method, HttpRequest.BodyPublishers.noBody());
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
        String baseUrl = Objects.requireNonNull(sonatypeUrl, "sonatypeUrl must not be null").replaceAll("/+$", "");
        return URI.create(baseUrl + "/" + path.replaceFirst("^/+", ""));
    }

    private List<Vulnerability> toVulnerabilities(JsonNode report) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();
        for (JsonNode component : report.path("components")) {
            JsonNode coordinates = component.path("componentIdentifier").path("coordinates");
            for (JsonNode issue : component.path("securityData").path("securityIssues")) {
                vulnerabilities.add(new Vulnerability(
                        coordinates.path("artifactId").asText(null),
                        coordinates.path("groupId").asText(null),
                        coordinates.path("version").asText(null),
                        issue.path("threatCategory").asText(issue.path("severity").asText(null)),
                        issue.path("description").asText(issue.path("reference").asText(null)),
                        firstPresent(issue, "versionToFix", "fixVersion", "remediation.version")
                ));
            }
        }
        return List.copyOf(vulnerabilities);
    }

    private String firstPresent(JsonNode node, String... paths) {
        for (String path : paths) {
            JsonNode candidate = node.at("/" + path.replace(".", "/"));
            if (!candidate.isMissingNode() && !candidate.isNull()) {
                return candidate.asText();
            }
        }
        return null;
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

package com.vulncheck;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;

/** Nexus Repository 3 adapter backed by the Components Search REST API. */
public final class NexusComponentVersionRepository implements ComponentVersionRepository {

    private final NexusRepositoryConfiguration configuration;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final ConcurrentMap<String, List<String>> cache = new ConcurrentHashMap<>();
    private final ConcurrentMap<String, Boolean> availabilityCache = new ConcurrentHashMap<>();
    private final AtomicBoolean repositoryValidated = new AtomicBoolean();

    public NexusComponentVersionRepository(NexusRepositoryConfiguration configuration) {
        this(
                configuration,
                HttpClient.newBuilder().connectTimeout(configuration.requestTimeout()).build(),
                new ObjectMapper()
        );
    }

    NexusComponentVersionRepository(
            NexusRepositoryConfiguration configuration,
            HttpClient httpClient,
            ObjectMapper objectMapper
    ) {
        this.configuration = Objects.requireNonNull(configuration, "configuration must not be null");
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient must not be null");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    }

    @Override
    public List<String> findVersions(ComponentCoordinate component) {
        validateRepository();
        String key = component.groupId() + ":" + component.artifactId();
        return cache.computeIfAbsent(key, ignored -> loadVersions(component));
    }

    @Override
    public boolean isAvailable(ComponentCoordinate component, String extension) {
        if (!findVersions(component).contains(component.version())) {
            return false;
        }
        String normalizedExtension = extension == null || extension.isBlank() ? "jar" : extension;
        String key = component.groupId() + ":" + component.artifactId() + ":"
                + component.version() + ":" + normalizedExtension;
        return availabilityCache.computeIfAbsent(
                key, ignored -> probeArtifact(component, normalizedExtension)
        );
    }

    private List<String> loadVersions(ComponentCoordinate component) {
        Set<String> versions = new LinkedHashSet<>();
        String continuationToken = null;

        do {
            JsonNode response = get(component, continuationToken);
            JsonNode items = response.path("items");
            if (items.isArray()) {
                items.forEach(item -> {
                    String version = item.path("version").asText(null);
                    boolean mavenComponent = "maven2".equals(item.path("format").asText());
                    boolean hasPom = item.path("assets").isArray()
                            && java.util.stream.StreamSupport.stream(item.path("assets").spliterator(), false)
                            .map(asset -> asset.path("path").asText(""))
                            .anyMatch(path -> path.endsWith(".pom"));
                    if (mavenComponent && hasPom && version != null && !version.isBlank()) {
                        versions.add(version);
                    }
                });
            }
            continuationToken = response.path("continuationToken").isNull()
                    ? null
                    : response.path("continuationToken").asText(null);
        } while (continuationToken != null && !continuationToken.isBlank());

        return List.copyOf(versions);
    }

    private void validateRepository() {
        if (repositoryValidated.get()) {
            return;
        }
        JsonNode repository = getJson("/service/rest/v1/repositories/" + encodePathSegment(configuration.repository()),
                "Nexus repository validation");
        if (!"maven2".equals(repository.path("format").asText())) {
            throw new VersionRepositoryException("Nexus repository " + configuration.repository()
                    + " is not a maven2 repository");
        }
        repositoryValidated.set(true);
    }

    private JsonNode get(ComponentCoordinate component, String continuationToken) {
        StringBuilder path = new StringBuilder("/service/rest/v1/search?repository=")
                .append(encode(configuration.repository()))
                .append("&group=").append(encode(component.groupId()))
                .append("&name=").append(encode(component.artifactId()));
        if (continuationToken != null) {
            path.append("&continuationToken=").append(encode(continuationToken));
        }

        return getJson(path.toString(), "Nexus version search");
    }

    private JsonNode getJson(String path, String operation) {
        HttpRequest.Builder request = HttpRequest.newBuilder(resolve(path))
                .timeout(configuration.requestTimeout())
                .header("Accept", "application/json")
                .GET();
        addAuthorization(request);

        try {
            HttpResponse<String> response = httpClient.send(request.build(), HttpResponse.BodyHandlers.ofString());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new VersionRepositoryException(
                        operation + " failed with HTTP " + response.statusCode() + ": " + response.body()
                );
            }
            return objectMapper.readTree(response.body());
        } catch (IOException exception) {
            throw new VersionRepositoryException(operation + " failed", exception);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new VersionRepositoryException(operation + " was interrupted", exception);
        }
    }

    private boolean probeArtifact(ComponentCoordinate component, String extension) {
        URI artifact = resolve(repositoryArtifactPath(component, extension));
        HttpRequest.Builder head = HttpRequest.newBuilder(artifact)
                .timeout(configuration.requestTimeout())
                .method("HEAD", HttpRequest.BodyPublishers.noBody());
        addAuthorization(head);
        int status = sendStatus(head.build(), "Nexus artifact availability probe");
        if (status == 405) {
            HttpRequest.Builder rangedGet = HttpRequest.newBuilder(artifact)
                    .timeout(configuration.requestTimeout())
                    .header("Range", "bytes=0-0")
                    .GET();
            addAuthorization(rangedGet);
            status = sendStatus(rangedGet.build(), "Nexus artifact availability probe");
        }
        if (status >= 200 && status < 300) {
            return true;
        }
        if (status == 403 || status == 404) {
            return false;
        }
        throw new VersionRepositoryException(
                "Nexus artifact availability probe failed with HTTP " + status + " for " + artifact
        );
    }

    private int sendStatus(HttpRequest request, String operation) {
        try {
            return httpClient.send(request, HttpResponse.BodyHandlers.discarding()).statusCode();
        } catch (IOException exception) {
            throw new VersionRepositoryException(operation + " failed", exception);
        } catch (InterruptedException exception) {
            Thread.currentThread().interrupt();
            throw new VersionRepositoryException(operation + " was interrupted", exception);
        }
    }

    private String repositoryArtifactPath(ComponentCoordinate component, String extension) {
        String groupPath = java.util.Arrays.stream(component.groupId().split("\\."))
                .map(this::encodePathSegment)
                .collect(java.util.stream.Collectors.joining("/"));
        String artifact = encodePathSegment(component.artifactId());
        String version = encodePathSegment(component.version());
        return "/repository/" + encodePathSegment(configuration.repository()) + "/" + groupPath + "/"
                + artifact + "/" + version + "/" + artifact + "-" + version + "."
                + encodePathSegment(extension);
    }

    private void addAuthorization(HttpRequest.Builder request) {
        if (configuration.bearerToken() != null && !configuration.bearerToken().isBlank()) {
            request.header("Authorization", "Bearer " + configuration.bearerToken());
            return;
        }
        if ((configuration.username() != null && !configuration.username().isBlank())
                || (configuration.password() != null && !configuration.password().isBlank())) {
            String credentials = Objects.toString(configuration.username(), "") + ":"
                    + Objects.toString(configuration.password(), "");
            request.header("Authorization", "Basic " + Base64.getEncoder()
                    .encodeToString(credentials.getBytes(StandardCharsets.UTF_8)));
        }
    }

    private URI resolve(String path) {
        return URI.create(configuration.baseUrl().replaceAll("/+$", "") + path);
    }

    private String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    private String encodePathSegment(String value) {
        return encode(value).replace("+", "%20");
    }
}

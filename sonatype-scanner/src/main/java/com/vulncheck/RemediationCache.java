package com.vulncheck;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

/**
 * Disk-based cache for Sonatype remediation responses.
 * Caches by component coordinate (groupId:artifactId:version) for 24 hours.
 */
public final class RemediationCache {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Duration TTL = Duration.ofHours(24);
    private final Path cacheDir;

    public RemediationCache() {
        this(Path.of(System.getProperty("user.home"), ".cache", "vulnfix", "remediation"));
    }

    public RemediationCache(Path cacheDir) {
        this.cacheDir = cacheDir;
        try {
            Files.createDirectories(cacheDir);
        } catch (IOException ignored) {
        }
    }

    public Optional<JsonNode> get(String groupId, String artifactId, String version) {
        Path file = cacheFile(groupId, artifactId, version);
        if (!Files.isRegularFile(file)) return Optional.empty();

        try {
            // Check TTL
            Instant modified = Files.getLastModifiedTime(file).toInstant();
            if (Instant.now().isAfter(modified.plus(TTL))) {
                Files.deleteIfExists(file);
                return Optional.empty();
            }
            return Optional.of(MAPPER.readTree(Files.readString(file)));
        } catch (IOException e) {
            return Optional.empty();
        }
    }

    public void put(String groupId, String artifactId, String version, JsonNode response) {
        Path file = cacheFile(groupId, artifactId, version);
        try {
            Files.createDirectories(file.getParent());
            Files.writeString(file, MAPPER.writeValueAsString(response));
        } catch (IOException ignored) {
        }
    }

    private Path cacheFile(String groupId, String artifactId, String version) {
        // Use groupId/artifactId/version.json structure
        String safeVersion = version.replace("/", "_").replace("\\", "_");
        return cacheDir.resolve(groupId).resolve(artifactId).resolve(safeVersion + ".json");
    }
}

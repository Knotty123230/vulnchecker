package com.vulncheck;

import java.time.Duration;

public record NexusRepositoryConfiguration(
        String baseUrl,
        String repository,
        String username,
        String password,
        String bearerToken,
        Duration requestTimeout
) {
    public NexusRepositoryConfiguration {
        if (baseUrl == null || baseUrl.isBlank()) {
            throw new IllegalArgumentException("Nexus baseUrl must not be blank");
        }
        if (repository == null || repository.isBlank()) {
            throw new IllegalArgumentException("Nexus repository must not be blank");
        }
        requestTimeout = requestTimeout == null ? Duration.ofSeconds(30) : requestTimeout;
    }
}

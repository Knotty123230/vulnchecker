package com.vulncheck;

import javax.annotation.Nonnull;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.time.Duration;
import java.util.EnumSet;
import java.util.Properties;

final class VulnScannerConfigStore {

    private static final String CONFIG_FILE_NAME = "config.properties";
    private static final String BASE_URL = "sonatype.base-url";
    private static final String USERNAME = "sonatype.username";
    private static final String PASSWORD = "sonatype.password";
    private static final String API_KEY = "sonatype.api-key";
    private static final String REQUEST_TIMEOUT = "sonatype.request-timeout";
    private static final String SCAN_TIMEOUT = "sonatype.scan-timeout";
    private static final String NEXUS_BASE_URL = "nexus.base-url";
    private static final String NEXUS_REPOSITORY = "nexus.repository";
    private static final String NEXUS_USERNAME = "nexus.username";
    private static final String NEXUS_PASSWORD = "nexus.password";
    private static final String NEXUS_BEARER_TOKEN = "nexus.bearer-token";
    private static final String NEXUS_REQUEST_TIMEOUT = "nexus.request-timeout";

    Path save(VulnScannerConfiguration configuration, boolean overwrite) {
        Path configPath = configPath();
        try {
            Files.createDirectories(configPath.getParent());
            if (!overwrite && Files.exists(configPath)) {
                throw new IllegalStateException("Configuration already exists at " + configPath + ". Use --force to overwrite it.");
            }
            setOwnerOnlyDirectoryPermissions(configPath.getParent());

            Properties properties = getProperties(configuration);

            try (OutputStream output = Files.newOutputStream(configPath)) {
                properties.store(output, "VulnScanner local configuration");
            }
            setOwnerOnlyFilePermissions(configPath);
            return configPath;
        } catch (IOException e) {
            throw new IllegalStateException("Unable to save configuration to " + configPath, e);
        }
    }

    @Nonnull
    private Properties getProperties(VulnScannerConfiguration configuration) {
        Properties properties = new Properties();
        SonatypeCredentials credentials = configuration.credentials();
        properties.setProperty(BASE_URL, credentials.baseUrl());
        properties.setProperty(USERNAME, credentials.username());
        properties.setProperty(PASSWORD, credentials.password());
        properties.setProperty(API_KEY, nullToEmpty(credentials.apiKey()));
        properties.setProperty(REQUEST_TIMEOUT, nullToEmpty(credentials.requestTimeout()));
        properties.setProperty(SCAN_TIMEOUT, nullToEmpty(credentials.scanTimeout()));
        NexusRepositoryConfiguration nexus = configuration.nexusRepository();
        if (nexus != null) {
            properties.setProperty(NEXUS_BASE_URL, nexus.baseUrl());
            properties.setProperty(NEXUS_REPOSITORY, nexus.repository());
            properties.setProperty(NEXUS_USERNAME, nullToEmpty(nexus.username()));
            properties.setProperty(NEXUS_PASSWORD, nullToEmpty(nexus.password()));
            properties.setProperty(NEXUS_BEARER_TOKEN, nullToEmpty(nexus.bearerToken()));
            properties.setProperty(NEXUS_REQUEST_TIMEOUT, nexus.requestTimeout().toString());
        }
        return properties;
    }

    VulnScannerConfiguration load() {
        Path configPath = configPath();
        if (!Files.isRegularFile(configPath)) {
            throw new IllegalStateException("Configuration not found at " + configPath + ". Run 'vulnfix init' first.");
        }

        Properties properties = new Properties();
        try (InputStream input = Files.newInputStream(configPath)) {
            properties.load(input);
        } catch (IOException e) {
            throw new IllegalStateException("Unable to read configuration from " + configPath, e);
        }

        return new VulnScannerConfiguration(
                new SonatypeCredentials(
                        required(properties, USERNAME),
                        required(properties, PASSWORD),
                        properties.getProperty(API_KEY),
                        required(properties, BASE_URL),
                        emptyToNull(properties.getProperty(REQUEST_TIMEOUT)),
                        emptyToNull(properties.getProperty(SCAN_TIMEOUT))
                ),
                nexusConfiguration(properties)
        );
    }

    private NexusRepositoryConfiguration nexusConfiguration(Properties properties) {
        String baseUrl = emptyToNull(properties.getProperty(NEXUS_BASE_URL));
        if (baseUrl == null) {
            return null;
        }
        String timeout = emptyToNull(properties.getProperty(NEXUS_REQUEST_TIMEOUT));
        return new NexusRepositoryConfiguration(
                baseUrl,
                required(properties, NEXUS_REPOSITORY),
                emptyToNull(properties.getProperty(NEXUS_USERNAME)),
                emptyToNull(properties.getProperty(NEXUS_PASSWORD)),
                emptyToNull(properties.getProperty(NEXUS_BEARER_TOKEN)),
                timeout == null ? Duration.ofSeconds(30) : Duration.parse(timeout)
        );
    }

    private Path configPath() {
        return Path.of(System.getProperty("user.home"), ".vulnscanner", CONFIG_FILE_NAME);
    }

    private String required(Properties properties, String key) {
        String value = properties.getProperty(key);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException("Missing required configuration value: " + key);
        }
        return value;
    }

    private String nullToEmpty(String value) {
        return value == null ? "" : value;
    }

    private String emptyToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private void setOwnerOnlyDirectoryPermissions(Path path) {
        try {
            Files.setPosixFilePermissions(path, EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE,
                    PosixFilePermission.OWNER_EXECUTE
            ));
        } catch (UnsupportedOperationException | IOException ignored) {
            // Windows and file systems without POSIX permissions use their default protection.
        }
    }

    private void setOwnerOnlyFilePermissions(Path path) {
        try {
            Files.setPosixFilePermissions(path, EnumSet.of(
                    PosixFilePermission.OWNER_READ,
                    PosixFilePermission.OWNER_WRITE
            ));
        } catch (UnsupportedOperationException | IOException ignored) {
            // Windows and file systems without POSIX permissions use their default protection.
        }
    }
}

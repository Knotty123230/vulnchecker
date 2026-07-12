package com.vulncheck;

import java.util.Objects;

record VulnScannerConfiguration(
        SonatypeCredentials credentials,
        NexusRepositoryConfiguration nexusRepository
) {

    VulnScannerConfiguration(SonatypeCredentials credentials) {
        this(credentials, null);
    }

    VulnScannerConfiguration {
        Objects.requireNonNull(credentials, "credentials must not be null");
    }
}

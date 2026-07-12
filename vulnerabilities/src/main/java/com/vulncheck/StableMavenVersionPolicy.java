package com.vulncheck;

import org.apache.maven.artifact.versioning.ComparableVersion;

import java.util.Comparator;
import java.util.List;
import java.util.Locale;

/** Selects the nearest stable Maven upgrades first to minimize patch blast radius. */
public final class StableMavenVersionPolicy implements VersionSelectionPolicy {

    private final int maximumCandidates;

    public StableMavenVersionPolicy() {
        this(Integer.MAX_VALUE);
    }

    public StableMavenVersionPolicy(int maximumCandidates) {
        if (maximumCandidates < 1) {
            throw new IllegalArgumentException("maximumCandidates must be positive");
        }
        this.maximumCandidates = maximumCandidates;
    }

    @Override
    public List<String> selectNewerVersions(String currentVersion, List<String> availableVersions) {
        ComparableVersion current = new ComparableVersion(currentVersion);
        return availableVersions.stream()
                .filter(version -> version != null && !version.isBlank())
                .filter(this::isStable)
                .distinct()
                .filter(version -> new ComparableVersion(version).compareTo(current) > 0)
                .sorted(Comparator.comparing(ComparableVersion::new))
                .limit(maximumCandidates)
                .toList();
    }

    private boolean isStable(String version) {
        String normalized = version.toLowerCase(Locale.ROOT);
        return !normalized.contains("snapshot")
                && !normalized.matches(".*(?:^|[.-])(alpha|beta|milestone|rc|cr|m)[.-]?\\d*.*");
    }
}

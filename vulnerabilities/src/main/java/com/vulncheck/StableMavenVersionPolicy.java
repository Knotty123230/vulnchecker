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
        String compatPrefix = compatibilityPrefix(currentVersion);
        return availableVersions.stream()
                .filter(version -> version != null && !version.isBlank())
                .filter(this::isStable)
                .filter(version -> compatibilityPrefix(version).equals(compatPrefix))
                .distinct()
                .filter(version -> new ComparableVersion(version).compareTo(current) > 0)
                .sorted(Comparator.comparing(ComparableVersion::new))
                .limit(maximumCandidates)
                .toList();
    }

    /**
     * Determines the compatibility boundary prefix for a version.
     * - Standard SemVer (3 segments like "1.2.3"): major version ("1")
     * - Extended versions (4+ segments like "4.1.133.Final"): major.minor ("4.1")
     * This prevents 4.1.x → 4.2.x (breaking in Netty-style versioning)
     * while allowing 1.2.0 → 1.5.0 → 2.0.0 for standard SemVer.
     */
    private String compatibilityPrefix(String version) {
        String[] segments = version.split("[.-]");
        int numericSegments = 0;
        for (String seg : segments) {
            if (seg.matches("\\d+")) numericSegments++;
            else break;
        }
        // 4+ numeric segments (like 4.1.133.x) → lock on major.minor
        if (numericSegments >= 4 || (numericSegments == 3 && segments.length > 3)) {
            // e.g., "4.1.133.Final" → "4.1"
            return extractMajorMinor(version);
        }
        // Standard 2-3 segments (like 1.5.0, 2.0.0) → lock on major only
        return extractMajor(version);
    }

    private String extractMajor(String version) {
        int dot = version.indexOf('.');
        return dot > 0 ? version.substring(0, dot) : version;
    }

    /**
     * For most libraries, same major version means compatible.
     * For some (like Netty 4.1.x vs 4.2.x), minor version changes are breaking.
     * We use major.minor matching to be safe.
     */
    private boolean sameMajor(String version, String expectedMajor) {
        String major = extractMajor(version);
        return major.equals(expectedMajor);
    }

    /**
     * Extracts major.minor prefix (e.g., "4.1" from "4.1.133.Final").
     */
    private String extractMajorMinor(String version) {
        int firstDot = version.indexOf('.');
        if (firstDot < 0) return version;
        int secondDot = version.indexOf('.', firstDot + 1);
        return secondDot > 0 ? version.substring(0, secondDot) : version;
    }

    private boolean isStable(String version) {
        String normalized = version.toLowerCase(Locale.ROOT);
        return !normalized.contains("snapshot")
                && !normalized.matches(".*(?:^|[.-])(alpha|beta|milestone|rc|cr|m)[.-]?\\d*.*");
    }
}

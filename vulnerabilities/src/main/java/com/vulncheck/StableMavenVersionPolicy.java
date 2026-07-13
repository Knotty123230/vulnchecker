package com.vulncheck;

import org.apache.maven.artifact.versioning.ComparableVersion;

import java.util.Comparator;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/** Selects a bounded set of stable Maven upgrades and avoids speculative release-line jumps. */
public final class StableMavenVersionPolicy implements VersionSelectionPolicy {

    private final int maximumCandidates;

    public StableMavenVersionPolicy() {
        this(3);
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
        String releaseLine = MavenReleaseLine.prefix(currentVersion);
        List<String> newer = availableVersions.stream()
                .filter(version -> version != null && !version.isBlank())
                .filter(this::isStable)
                .distinct()
                .filter(version -> new ComparableVersion(version).compareTo(current) > 0)
                .sorted(Comparator.comparing(ComparableVersion::new))
                .toList();

        List<String> sameReleaseLine = newer.stream()
                .filter(version -> MavenReleaseLine.prefix(version).equals(releaseLine))
                .toList();
        if (!sameReleaseLine.isEmpty()) {
            return edgeCandidates(sameReleaseLine);
        }

        return List.of();
    }

    private List<String> edgeCandidates(List<String> versions) {
        if (versions.size() <= maximumCandidates) {
            return versions;
        }
        List<String> selected = new ArrayList<>();
        selected.add(versions.getFirst());
        if (maximumCandidates > 1) {
            selected.add(versions.getLast());
        }
        return List.copyOf(selected);
    }

    private boolean isStable(String version) {
        String normalized = version.toLowerCase(Locale.ROOT);
        return !normalized.contains("snapshot")
                && !normalized.matches(".*(?:^|[.-])(alpha|beta|milestone|rc|cr|m)[.-]?\\d*.*");
    }
}

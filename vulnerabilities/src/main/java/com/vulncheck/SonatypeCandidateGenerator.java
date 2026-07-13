package com.vulncheck;

import java.util.List;
import java.util.Objects;

/** Generates candidates only when Sonatype has supplied an explicit replacement version. */
public final class SonatypeCandidateGenerator implements CandidateGenerator {

    @Override
    public List<PatchCandidate> generate(
            MutationPoint mutationPoint,
            RemediationCandidate remediation,
            Vulnerability vulnerability
    ) {
        if (remediation == null) {
            return List.of();
        }
        ComponentCoordinate replacement = replacementFor(mutationPoint, remediation);
        if (replacement == null || mutationPoint.resolvedNode() == null) {
            return List.of();
        }

        String currentVersion = mutationPoint.component().version();
        String newVersion = replacement.version();
        int priority = isCompatibleUpgrade(currentVersion, newVersion) ? 0 : 50;

        FixCandidate candidate = new FixCandidate(
                vulnerability,
                mutationPoint.resolvedNode(),
                new FixCandidate.ComponentFix(List.of(), replacement),
                mutationPoint.type() == MutationType.UPDATE_DIRECT_DEPENDENCY,
                sonatypeParentFixes(remediation)
        );
        return List.of(new PatchCandidate(mutationPoint, candidate, priority));
    }

    /**
     * Checks if the version upgrade is compatible (no breaking major/minor changes).
     * Same logic as StableMavenVersionPolicy.compatibilityPrefix.
     */
    private boolean isCompatibleUpgrade(String currentVersion, String newVersion) {
        if (currentVersion == null || newVersion == null) return true;
        String currentPrefix = compatibilityPrefix(currentVersion);
        String newPrefix = compatibilityPrefix(newVersion);
        return currentPrefix.equals(newPrefix);
    }

    private String compatibilityPrefix(String version) {
        String[] segments = version.split("[.-]");
        int numericSegments = 0;
        for (String seg : segments) {
            if (seg.matches("\\d+")) numericSegments++;
            else break;
        }
        if (numericSegments >= 4 || (numericSegments == 3 && segments.length > 3)) {
            return extractMajorMinor(version);
        }
        return extractMajor(version);
    }

    private String extractMajor(String version) {
        int dot = version.indexOf('.');
        return dot > 0 ? version.substring(0, dot) : version;
    }

    private String extractMajorMinor(String version) {
        int firstDot = version.indexOf('.');
        if (firstDot < 0) return version;
        int secondDot = version.indexOf('.', firstDot + 1);
        return secondDot > 0 ? version.substring(0, secondDot) : version;
    }

    private ComponentCoordinate replacementFor(MutationPoint mutationPoint, RemediationCandidate remediation) {
        if (mutationPoint.type() == MutationType.UPDATE_DIRECT_DEPENDENCY) {
            return remediation.directDependency() ? remediation.target() : null;
        }
        if (mutationPoint.type() == MutationType.UPDATE_PROPERTY
                || mutationPoint.type() == MutationType.UPDATE_DEPENDENCY_MANAGEMENT) {
            return remediation.target();
        }

        return sonatypeParentFixes(remediation).stream()
                .map(FixCandidate.ComponentFix::coordinate)
                .filter(target -> sameComponent(target, mutationPoint.component()))
                .findFirst()
                .orElse(null);
    }

    private List<FixCandidate.ComponentFix> sonatypeParentFixes(RemediationCandidate remediation) {
        if (remediation.parentCandidates() == null) {
            return List.of();
        }

        return remediation.parentCandidates().stream()
                .filter(Objects::nonNull)
                .filter(this::hasCoordinates)
                .distinct()
                .map(target -> new FixCandidate.ComponentFix(List.of(), target))
                .toList();
    }

    private boolean sameComponent(ComponentCoordinate first, ComponentCoordinate second) {
        return first.groupId().equals(second.groupId())
                && first.artifactId().equals(second.artifactId());
    }

    private boolean hasCoordinates(ComponentCoordinate coordinate) {
        return coordinate.groupId() != null && coordinate.artifactId() != null && coordinate.version() != null;
    }
}

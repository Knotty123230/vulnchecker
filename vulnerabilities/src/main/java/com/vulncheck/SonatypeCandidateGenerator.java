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

        FixCandidate candidate = new FixCandidate(
                vulnerability,
                mutationPoint.resolvedNode(),
                new FixCandidate.ComponentFix(List.of(), replacement),
                mutationPoint.type() == MutationType.UPDATE_DIRECT_DEPENDENCY,
                sonatypeParentFixes(remediation)
        );
        return List.of(new PatchCandidate(mutationPoint, candidate));
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

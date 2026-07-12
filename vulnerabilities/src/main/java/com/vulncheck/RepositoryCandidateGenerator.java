package com.vulncheck;

import java.util.List;
import java.util.Objects;

/** Generates fallback candidates from a repository catalog when remediation is absent or incomplete. */
public final class RepositoryCandidateGenerator implements CandidateGenerator {

    private static final int REPOSITORY_PRIORITY_BASE = 100;

    private final ComponentVersionRepository versionRepository;
    private final VersionSelectionPolicy versionSelectionPolicy;

    public RepositoryCandidateGenerator(
            ComponentVersionRepository versionRepository,
            VersionSelectionPolicy versionSelectionPolicy
    ) {
        this.versionRepository = Objects.requireNonNull(versionRepository, "versionRepository must not be null");
        this.versionSelectionPolicy = Objects.requireNonNull(versionSelectionPolicy, "versionSelectionPolicy must not be null");
    }

    @Override
    public List<PatchCandidate> generate(
            MutationPoint mutationPoint,
            RemediationCandidate remediation,
            Vulnerability vulnerability
    ) {
        if (mutationPoint.resolvedNode() == null) {
            return List.of();
        }

        ComponentCoordinate target = repositoryTarget(mutationPoint, vulnerability);
        List<String> selected = versionSelectionPolicy.selectNewerVersions(
                target.version(), versionRepository.findVersions(target)
        );

        return java.util.stream.IntStream.range(0, selected.size())
                .mapToObj(index -> toCandidate(
                        mutationPoint, vulnerability, target, selected.get(index), REPOSITORY_PRIORITY_BASE + index
                ))
                .toList();
    }

    private PatchCandidate toCandidate(
            MutationPoint mutationPoint,
            Vulnerability vulnerability,
            ComponentCoordinate target,
            String version,
            int priority
    ) {
        ComponentCoordinate replacement = new ComponentCoordinate(target.groupId(), target.artifactId(), version);
        FixCandidate fix = new FixCandidate(
                vulnerability,
                mutationPoint.resolvedNode(),
                new FixCandidate.ComponentFix(List.of(), replacement),
                mutationPoint.type() == MutationType.UPDATE_DIRECT_DEPENDENCY,
                List.of()
        );
        return new PatchCandidate(mutationPoint, fix, priority);
    }

    private ComponentCoordinate repositoryTarget(MutationPoint point, Vulnerability vulnerability) {
        return switch (point.type()) {
            case UPDATE_PROPERTY, UPDATE_DIRECT_DEPENDENCY, UPDATE_DEPENDENCY_MANAGEMENT ->
                    new ComponentCoordinate(
                            vulnerability.getGroupId(), vulnerability.getArtifactId(), vulnerability.getVersion()
                    );
            case UPDATE_IMPORTED_BOM, UPDATE_PARENT_DEPENDENCY, UPDATE_PARENT_POM -> point.component();
        };
    }
}

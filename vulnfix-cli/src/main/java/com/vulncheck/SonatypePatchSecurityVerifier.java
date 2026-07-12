package com.vulncheck;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;

/** Re-resolves the patched project and asks Sonatype whether the original vulnerability remains. */
final class SonatypePatchSecurityVerifier implements PatchSecurityVerifier {

    private final String projectId;
    private final DependencyNodeFinder dependencyNodeFinder;
    private final VulnerabilitiesScanner vulnerabilitiesScanner;

    SonatypePatchSecurityVerifier(
            String projectId,
            DependencyNodeFinder dependencyNodeFinder,
            VulnerabilitiesScanner vulnerabilitiesScanner
    ) {
        this.projectId = Objects.requireNonNull(projectId, "projectId must not be null");
        this.dependencyNodeFinder = Objects.requireNonNull(dependencyNodeFinder, "dependencyNodeFinder must not be null");
        this.vulnerabilitiesScanner = Objects.requireNonNull(vulnerabilitiesScanner, "vulnerabilitiesScanner must not be null");
    }

    @Override
    public SecurityVerificationResult verify(Path projectPath, PatchCandidate candidate) {
        DependencyNode dependencyTree = dependencyNodeFinder.find(projectPath);
        if (dependencyTree == null) {
            return SecurityVerificationResult.unsafe("unable to rebuild dependency tree");
        }

        List<Vulnerability> remaining = vulnerabilitiesScanner.scanDependencies(projectId, dependencyTree);
        Vulnerability original = candidate.candidate().vulnerability();
        boolean stillVulnerable = remaining.stream().anyMatch(vulnerability ->
                original.getId().equals(vulnerability.getId())
                        && original.getGroupId().equals(vulnerability.getGroupId())
                        && original.getArtifactId().equals(vulnerability.getArtifactId())
        );
        return stillVulnerable
                ? SecurityVerificationResult.unsafe("Sonatype still reports " + original.getId())
                : SecurityVerificationResult.safeResult();
    }
}

package com.vulncheck;

import java.nio.file.Path;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/** Re-resolves the patched project and asks Sonatype whether the original vulnerability remains. */
final class SonatypePatchSecurityVerifier implements PatchSecurityVerifier {

    private final String projectId;
    private final DependencyNodeFinder dependencyNodeFinder;
    private final VulnerabilitiesScanner vulnerabilitiesScanner;
    private final Set<String> baselineFindings;

    SonatypePatchSecurityVerifier(
            String projectId,
            DependencyNodeFinder dependencyNodeFinder,
            VulnerabilitiesScanner vulnerabilitiesScanner
    ) {
        this(projectId, dependencyNodeFinder, vulnerabilitiesScanner, List.of());
    }

    SonatypePatchSecurityVerifier(
            String projectId,
            DependencyNodeFinder dependencyNodeFinder,
            VulnerabilitiesScanner vulnerabilitiesScanner,
            List<Vulnerability> baseline
    ) {
        this.projectId = Objects.requireNonNull(projectId, "projectId must not be null");
        this.dependencyNodeFinder = Objects.requireNonNull(dependencyNodeFinder, "dependencyNodeFinder must not be null");
        this.vulnerabilitiesScanner = Objects.requireNonNull(vulnerabilitiesScanner, "vulnerabilitiesScanner must not be null");
        this.baselineFindings = Objects.requireNonNull(baseline, "baseline must not be null").stream()
                .map(this::findingKey)
                .collect(Collectors.toUnmodifiableSet());
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
        if (stillVulnerable) {
            return SecurityVerificationResult.unsafe("Sonatype still reports " + original.getId());
        }
        Vulnerability regression = remaining.stream()
                .filter(this::isHighSeverity)
                .filter(vulnerability -> !baselineFindings.contains(findingKey(vulnerability)))
                .findFirst()
                .orElse(null);
        return regression == null
                ? SecurityVerificationResult.safeResult()
                : SecurityVerificationResult.unsafe("patch introduced " + regression.getId() + " on "
                + regression.component() + ":" + regression.getVersion());
    }

    private boolean isHighSeverity(Vulnerability vulnerability) {
        String severity = vulnerability.getSeverity();
        return severity != null && (severity.equalsIgnoreCase("critical")
                || severity.equalsIgnoreCase("severe") || severity.equalsIgnoreCase("high"));
    }

    private String findingKey(Vulnerability vulnerability) {
        return vulnerability.getId() + "|" + vulnerability.getGroupId() + ":"
                + vulnerability.getArtifactId() + ":" + vulnerability.getVersion();
    }
}

package com.vulncheck;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SonatypePatchSecurityVerifierTest {

    @Test
    void rejectsPatchWhenOriginalFindingRemains() {
        Vulnerability original = vulnerability("CVE-old", "library", "1.0.0", "high");
        var verifier = verifier(List.of(original), List.of(original));

        assertFalse(verifier.verify(null, candidate(original)).safe());
    }

    @Test
    void rejectsNewHighSeverityRegression() {
        Vulnerability original = vulnerability("CVE-old", "library", "1.0.0", "high");
        Vulnerability regression = vulnerability("CVE-new", "other-library", "2.0.0", "critical");
        var verifier = verifier(List.of(original), List.of(regression));

        assertFalse(verifier.verify(null, candidate(original)).safe());
    }

    @Test
    void acceptsPatchWhenOriginalFindingIsGoneAndNoRegressionAppears() {
        Vulnerability original = vulnerability("CVE-old", "library", "1.0.0", "high");
        var verifier = verifier(List.of(original), List.of());

        assertTrue(verifier.verify(null, candidate(original)).safe());
    }

    private SonatypePatchSecurityVerifier verifier(List<Vulnerability> baseline, List<Vulnerability> afterPatch) {
        DependencyNode tree = new DependencyNode("application", "com.example", "1.0.0", "compile", List.of());
        return new SonatypePatchSecurityVerifier("application", ignored -> tree,
                (projectId, dependencyNode) -> afterPatch, baseline);
    }

    private PatchCandidate candidate(Vulnerability vulnerability) {
        ComponentCoordinate current = new ComponentCoordinate(
                vulnerability.getGroupId(), vulnerability.getArtifactId(), vulnerability.getVersion()
        );
        ComponentCoordinate replacement = new ComponentCoordinate(
                vulnerability.getGroupId(), vulnerability.getArtifactId(), "1.1.0"
        );
        vulnerability.setRemediationCandidate(new RemediationCandidate("upgrade", replacement, true, List.of()));
        DependencyNode node = new DependencyNode(
                vulnerability.getArtifactId(), vulnerability.getGroupId(), vulnerability.getVersion(), "compile", List.of()
        );
        return new PatchCandidate(
                new MutationPoint(
                        MutationType.UPDATE_DIRECT_DEPENDENCY,
                        current,
                        node,
                        new VersionOwner(VersionOwnerType.DIRECT_DEPENDENCY, current, null, null)
                ),
                new FixCandidate(
                        vulnerability, node, new FixCandidate.ComponentFix(List.of(), replacement), true, List.of()
                )
        );
    }

    private Vulnerability vulnerability(String id, String artifactId, String version, String severity) {
        return new Vulnerability(id, "com.example", artifactId, version, severity, "", "");
    }
}

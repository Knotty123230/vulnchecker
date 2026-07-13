package com.vulncheck;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class MavenProjectBuildVerifierTest {

    private final MavenProjectBuildVerifier verifier = new MavenProjectBuildVerifier();

    @Test
    void rejectsGraphThatStillContainsVulnerableVersion() {
        PatchCandidate candidate = candidate();
        MavenDependencyTreeNode root = rootWith("1.0.0");

        assertEquals(
                "Vulnerable dependency is still resolved: com.example:library:1.0.0",
                verifier.verifyExpectedResolution(root, candidate)
        );
    }

    @Test
    void rejectsGraphThatDoesNotContainExpectedFixedVersion() {
        PatchCandidate candidate = candidate();
        MavenDependencyTreeNode root = new MavenDependencyTreeNode(
                "com.example", "application", "1.0.0", List.of()
        );

        assertEquals(
                "Expected fixed dependency is not resolved: com.example:library:1.1.0",
                verifier.verifyExpectedResolution(root, candidate)
        );
    }

    @Test
    void acceptsGraphWithExpectedFixedVersion() {
        assertNull(verifier.verifyExpectedResolution(rootWith("1.1.0"), candidate()));
    }

    private MavenDependencyTreeNode rootWith(String version) {
        return new MavenDependencyTreeNode(
                "com.example",
                "application",
                "1.0.0",
                List.of(new MavenDependencyTreeNode("com.example", "library", version, List.of()))
        );
    }

    private PatchCandidate candidate() {
        Vulnerability vulnerability = new Vulnerability(
                "CVE-test", "com.example", "library", "1.0.0", "high", "", ""
        );
        ComponentCoordinate replacement = new ComponentCoordinate("com.example", "library", "1.1.0");
        vulnerability.setRemediationCandidate(new RemediationCandidate("upgrade", replacement, true, List.of()));
        DependencyNode node = new DependencyNode("library", "com.example", "1.0.0", "compile", List.of());
        ComponentCoordinate current = new ComponentCoordinate("com.example", "library", "1.0.0");
        MutationPoint point = new MutationPoint(
                MutationType.UPDATE_DIRECT_DEPENDENCY,
                current,
                node,
                new VersionOwner(VersionOwnerType.DIRECT_DEPENDENCY, current, null, null)
        );
        return new PatchCandidate(
                point,
                new FixCandidate(
                        vulnerability, node, new FixCandidate.ComponentFix(List.of(), replacement), true, List.of()
                )
        );
    }
}

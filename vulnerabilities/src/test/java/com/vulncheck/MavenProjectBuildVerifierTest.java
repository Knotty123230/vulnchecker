package com.vulncheck;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

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

    @Test
    void acceptsRepositoryVersionHigherThanMinimumRemediation() {
        PatchCandidate candidate = candidate("1.2.0");

        assertNull(verifier.verifyExpectedResolution(rootWith("1.2.0"), candidate));
    }

    @Test
    void acceptsUnchangedPreExistingConvergenceConflict() {
        String baseline = convergence("com.example", "shared", "1.0.0", "2.0.0");

        assertNull(verifier.convergenceRegression(baseline, baseline));
    }

    @Test
    void rejectsNewConvergenceConflict() {
        String baseline = convergence("com.example", "shared", "1.0.0", "2.0.0");
        String current = baseline + System.lineSeparator()
                + convergence("com.example", "new-conflict", "3.0.0", "4.0.0");

        String failure = verifier.convergenceRegression(baseline, current);

        assertTrue(failure.contains("com.example:new-conflict"));
        assertTrue(failure.contains("new conflict"));
    }

    @Test
    void rejectsAdditionalVersionOnExistingConflict() {
        String baseline = convergence("com.example", "shared", "1.0.0", "2.0.0");
        String current = convergence("com.example", "shared", "1.0.0", "2.0.0", "3.0.0");

        String failure = verifier.convergenceRegression(baseline, current);

        assertTrue(failure.contains("com.example:shared"));
        assertTrue(failure.contains("was"));
    }

    private String convergence(String groupId, String artifactId, String... versions) {
        StringBuilder output = new StringBuilder("Dependency convergence error for ")
                .append(groupId).append(':').append(artifactId).append(":jar:")
                .append(versions[0]).append(". Paths to dependency are:\n");
        for (String version : versions) {
            output.append("+-").append(groupId).append(':').append(artifactId)
                    .append(":jar:").append(version).append(":compile\n");
        }
        return output.toString();
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
        return candidate("1.1.0");
    }

    private PatchCandidate candidate(String replacementVersion) {
        Vulnerability vulnerability = new Vulnerability(
                "CVE-test", "com.example", "library", "1.0.0", "high", "", ""
        );
        ComponentCoordinate minimum = new ComponentCoordinate("com.example", "library", "1.1.0");
        ComponentCoordinate replacement = new ComponentCoordinate(
                "com.example", "library", replacementVersion
        );
        vulnerability.setRemediationCandidate(new RemediationCandidate("upgrade", minimum, true, List.of()));
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

package com.vulncheck;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class VulnerabilitiesFixerTest {

    @Test
    void returnsDirectFixForSingleIndependentComponent() {
        DependencyNode jackson = node("com.fasterxml.jackson.core", "jackson-databind", "2.17.0");
        Vulnerability vulnerability = vulnerability("com.fasterxml.jackson.core", "jackson-databind", "2.17.0",
                "2.17.2", true, List.of());

        List<FixCandidate> candidates = fixer(vulnerability, jackson).findCandidates();

        assertEquals(1, candidates.size());
        assertEquals(jackson, candidates.getFirst().node());
        assertEquals("2.17.2", candidates.getFirst().replacement().coordinate().version());
        assertTrue(candidates.getFirst().replacement().availableVersions().isEmpty());
    }

    @Test
    void doesNotTreatOtherNettyArtifactsAsProofThatDirectFixConflicts() {
        DependencyNode handler = node("io.netty", "netty-handler", "4.1.100.Final");
        DependencyNode codec = node("io.netty", "netty-codec-http", "4.1.100.Final");
        DependencyNode application = node("example", "application", "1.0.0", List.of(handler, codec));
        Vulnerability vulnerability = vulnerability("io.netty", "netty-handler", "4.1.100.Final",
                "4.1.110.Final", true, List.of());

        List<FixCandidate> candidates = fixer(vulnerability, application, handler, codec).findCandidates();

        assertEquals(1, candidates.size());
        assertEquals(handler, candidates.getFirst().node());
        assertEquals("4.1.110.Final", candidates.getFirst().replacement().coordinate().version());
    }

    @Test
    void usesSonatypeParentTargetVersionForResolvedParentNode() {
        DependencyNode netty = node("io.netty", "netty-handler", "4.1.100.Final");
        DependencyNode reactorNetty = node("io.projectreactor.netty", "reactor-netty", "1.1.0", List.of(netty));
        ComponentCoordinate sonatypeParent = new ComponentCoordinate("io.projectreactor.netty", "reactor-netty", "1.1.20");
        Vulnerability vulnerability = vulnerability("io.netty", "netty-handler", "4.1.100.Final",
                "4.1.110.Final", false, List.of(sonatypeParent));

        List<FixCandidate> candidates = fixer(vulnerability, reactorNetty, netty).findCandidates();

        assertEquals(1, candidates.size());
        assertEquals(reactorNetty, candidates.getFirst().node());
        assertEquals(sonatypeParent, candidates.getFirst().replacement().coordinate());
    }

    @Test
    void doesNotCreateNoOpCandidateFromGraphAncestorWithoutVersionOwnerData() {
        DependencyNode netty = node("io.netty", "netty-handler", "4.1.100.Final");
        DependencyNode reactorNetty = node("io.projectreactor.netty", "reactor-netty", "1.1.0", List.of(netty));
        DependencyNode application = node("example", "application", "1.0.0", List.of(reactorNetty));
        Vulnerability vulnerability = vulnerability("io.netty", "netty-handler", "4.1.100.Final",
                "4.1.110.Final", false, List.of());

        List<FixCandidate> candidates = fixer(vulnerability, application, reactorNetty, netty).findCandidates();

        assertTrue(candidates.isEmpty());
    }

    @Test
    void keepsDirectFixAndSonatypeParentAsSeparateExplicitCandidates() {
        DependencyNode netty = node("io.netty", "netty-handler", "4.1.100.Final");
        DependencyNode reactorNetty = node("io.projectreactor.netty", "reactor-netty", "1.1.0", List.of(netty));
        ComponentCoordinate sonatypeParent = new ComponentCoordinate("io.projectreactor.netty", "reactor-netty", "1.1.20");
        Vulnerability vulnerability = vulnerability("io.netty", "netty-handler", "4.1.100.Final",
                "4.1.110.Final", true, List.of(sonatypeParent));

        List<FixCandidate> candidates = fixer(vulnerability, reactorNetty, netty).findCandidates();

        assertEquals(2, candidates.size());
        assertEquals(netty, candidates.getFirst().node());
        assertEquals(reactorNetty, candidates.get(1).node());
        assertEquals(sonatypeParent, candidates.get(1).replacement().coordinate());
    }

    @Test
    void rejectsSonatypeParentCandidateWhenItWouldNotChangeTheResolvedVersion() {
        DependencyNode netty = node("io.netty", "netty-handler", "4.1.100.Final");
        DependencyNode reactorNetty = node("io.projectreactor.netty", "reactor-netty", "1.1.0", List.of(netty));
        ComponentCoordinate noOpParent = new ComponentCoordinate("io.projectreactor.netty", "reactor-netty", "1.1.0");
        Vulnerability vulnerability = vulnerability("io.netty", "netty-handler", "4.1.100.Final",
                "4.1.110.Final", false, List.of(noOpParent));

        List<FixCandidate> candidates = fixer(vulnerability, reactorNetty, netty).findCandidates();

        assertTrue(candidates.isEmpty());
    }

    @Test
    void generatesImportedBomPatchUsingVulnerableNodeAsAnchor() {
        DependencyNode netty = node("io.netty", "netty-handler", "4.1.100.Final");
        DependencyGraph graph = DependencyGraph.empty();
        graph.addNode(netty);
        ComponentCoordinate vulnerable = new ComponentCoordinate("io.netty", "netty-handler", "4.1.100.Final");
        ComponentCoordinate currentBom = new ComponentCoordinate("io.netty", "netty-bom", "4.1.100.Final");
        ComponentCoordinate targetBom = new ComponentCoordinate("io.netty", "netty-bom", "4.1.110.Final");
        Vulnerability vulnerability = vulnerability("io.netty", "netty-handler", "4.1.100.Final",
                "4.1.110.Final", false, List.of(targetBom));
        EffectiveMavenModel model = new EffectiveMavenModel(List.of(new VersionOwnerBinding(
                vulnerable,
                List.of(new VersionOwner(VersionOwnerType.IMPORTED_BOM, currentBom, null, null))
        )));
        VulnerabilitiesFixer fixer = new VulnerabilitiesFixer(
                List.of(vulnerability),
                graph,
                model,
                new RemediationMutationPointResolver(new EffectiveModelVersionOwnerResolver()),
                new SonatypeCandidateGenerator(),
                new BasicCandidateEvaluator()
        );

        List<PatchCandidate> candidates = fixer.findPatchCandidates();

        assertEquals(1, candidates.size());
        assertEquals(MutationType.UPDATE_IMPORTED_BOM, candidates.getFirst().mutationPoint().type());
        assertEquals(targetBom, candidates.getFirst().candidate().replacement().coordinate());
    }

    private static VulnerabilitiesFixer fixer(Vulnerability vulnerability, DependencyNode... nodes) {
        DependencyGraph graph = DependencyGraph.empty();
        for (DependencyNode node : nodes) {
            graph.addNode(node);
        }
        return new VulnerabilitiesFixer(List.of(vulnerability), graph);
    }

    private static Vulnerability vulnerability(
            String groupId,
            String artifactId,
            String version,
            String targetVersion,
            boolean directDependency,
            List<ComponentCoordinate> parents
    ) {
        Vulnerability vulnerability = new Vulnerability("CVE-test", groupId, artifactId, version, "high", "", "");
        vulnerability.setRemediationCandidate(new RemediationCandidate(
                "upgrade", new ComponentCoordinate(groupId, artifactId, targetVersion), directDependency, parents
        ));
        return vulnerability;
    }

    private static DependencyNode node(String groupId, String artifactId, String version) {
        return node(groupId, artifactId, version, List.of());
    }

    private static DependencyNode node(String groupId, String artifactId, String version, List<DependencyNode> children) {
        return new DependencyNode(artifactId, groupId, version, "compile", children);
    }
}

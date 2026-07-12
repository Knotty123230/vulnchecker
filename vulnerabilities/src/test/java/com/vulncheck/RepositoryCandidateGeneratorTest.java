package com.vulncheck;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class RepositoryCandidateGeneratorTest {

    @Test
    void selectsOnlyNewerStableVersionsFromNearestToFarthest() {
        StableMavenVersionPolicy policy = new StableMavenVersionPolicy();

        List<String> selected = policy.selectNewerVersions(
                "1.2.0",
                List.of("2.0.0", "1.2.0", "1.3.0-RC1", "1.2.1", "1.1.9", "1.5.0", "2.0.0-SNAPSHOT")
        );

        assertEquals(List.of("1.2.1", "1.5.0", "2.0.0"), selected);
    }

    @Test
    void generatesRepositoryCandidatesWithoutSonatypeRemediation() {
        Vulnerability vulnerability = vulnerability(null);
        DependencyNode node = node();
        ComponentCoordinate component = component("1.2.0");
        MutationPoint point = new MutationPoint(
                MutationType.UPDATE_DIRECT_DEPENDENCY,
                component,
                node,
                new VersionOwner(VersionOwnerType.DIRECT_DEPENDENCY, component, null, null)
        );
        RepositoryCandidateGenerator generator = new RepositoryCandidateGenerator(
                ignored -> List.of("1.5.0", "1.2.1", "1.2.0"),
                new StableMavenVersionPolicy()
        );

        List<PatchCandidate> candidates = generator.generate(point, null, vulnerability);

        assertEquals(List.of("1.2.1", "1.5.0"), candidates.stream()
                .map(candidate -> candidate.candidate().replacement().coordinate().version())
                .toList());
        assertEquals(List.of(100, 101), candidates.stream().map(PatchCandidate::recommendationPriority).toList());
    }

    @Test
    void keepsSonatypeRecommendationFirstAndAddsHigherRepositoryVersions() {
        Vulnerability vulnerability = vulnerability("1.2.2");
        MutationPoint point = new MutationPoint(
                MutationType.UPDATE_DIRECT_DEPENDENCY,
                component("1.2.0"),
                node(),
                new VersionOwner(VersionOwnerType.DIRECT_DEPENDENCY, component("1.2.0"), null, null)
        );
        CandidateGenerator generator = new CompositeCandidateGenerator(List.of(
                new SonatypeCandidateGenerator(),
                new RepositoryCandidateGenerator(
                        ignored -> List.of("1.2.1", "1.2.2", "1.3.0"),
                        new StableMavenVersionPolicy()
                )
        ));

        List<PatchCandidate> candidates = generator.generate(
                point, vulnerability.getRemediationCandidate(), vulnerability
        );

        assertEquals(List.of("1.2.2", "1.2.1", "1.3.0"), candidates.stream()
                .map(candidate -> candidate.candidate().replacement().coordinate().version())
                .toList());
    }

    @Test
    void fixerUsesEffectiveModelAndRepositoryWhenRemediationIsMissing() {
        Vulnerability vulnerability = vulnerability(null);
        DependencyNode node = node();
        DependencyGraph graph = DependencyGraph.empty();
        graph.addNode(node);
        ComponentCoordinate component = component("1.2.0");
        EffectiveMavenModel model = new EffectiveMavenModel(List.of(new VersionOwnerBinding(
                component,
                List.of(new VersionOwner(VersionOwnerType.DIRECT_DEPENDENCY, component, null, null))
        )));
        CandidateGenerator generator = new RepositoryCandidateGenerator(
                ignored -> List.of("1.2.1"), new StableMavenVersionPolicy()
        );
        VulnerabilitiesFixer fixer = new VulnerabilitiesFixer(
                List.of(vulnerability),
                graph,
                model,
                new RemediationMutationPointResolver(new EffectiveModelVersionOwnerResolver()),
                generator,
                new BasicCandidateEvaluator()
        );

        List<PatchCandidate> candidates = fixer.findPatchCandidates();

        assertEquals(1, candidates.size());
        assertEquals("1.2.1", candidates.getFirst().candidate().replacement().coordinate().version());
    }

    @Test
    void usesNearestDirectDependencyAsVerifiedFallbackWhenVersionOwnerIsUnknown() {
        Vulnerability vulnerability = vulnerability(null);
        DependencyNode vulnerableNode = node();
        DependencyNode parentNode = new DependencyNode(
                "parent-library", "com.example", "3.0.0", "compile", List.of(vulnerableNode)
        );
        DependencyGraph graph = DependencyGraph.empty();
        graph.addNode(vulnerableNode);
        graph.addNode(parentNode);
        ComponentCoordinate application = new ComponentCoordinate("com.example", "application", "1.0.0");
        ComponentCoordinate parent = new ComponentCoordinate("com.example", "parent-library", "3.0.0");
        EffectiveMavenModel model = new EffectiveMavenModel(
                null,
                null,
                application,
                List.of(),
                List.of(),
                List.of(new DependencyPath(component("1.2.0"), List.of(application, parent, component("1.2.0"))))
        );
        CandidateGenerator generator = new RepositoryCandidateGenerator(
                coordinate -> coordinate.artifactId().equals("parent-library")
                        ? List.of("3.0.1")
                        : List.of(),
                new StableMavenVersionPolicy()
        );
        VulnerabilitiesFixer fixer = new VulnerabilitiesFixer(
                List.of(vulnerability),
                graph,
                model,
                new RemediationMutationPointResolver(new EffectiveModelVersionOwnerResolver()),
                generator,
                new BasicCandidateEvaluator()
        );

        List<PatchCandidate> candidates = fixer.findPatchCandidates();

        assertEquals(1, candidates.size());
        assertEquals(MutationType.UPDATE_PARENT_DEPENDENCY, candidates.getFirst().mutationPoint().type());
        assertEquals("parent-library", candidates.getFirst().candidate().replacement().coordinate().artifactId());
        assertEquals("3.0.1", candidates.getFirst().candidate().replacement().coordinate().version());
    }

    private Vulnerability vulnerability(String remediationVersion) {
        Vulnerability vulnerability = new Vulnerability(
                "CVE-test", "com.example", "library", "1.2.0", "high", "", ""
        );
        if (remediationVersion != null) {
            vulnerability.setRemediationCandidate(new RemediationCandidate(
                    "upgrade", component(remediationVersion), true, List.of()
            ));
        }
        return vulnerability;
    }

    private DependencyNode node() {
        return new DependencyNode("library", "com.example", "1.2.0", "compile", List.of());
    }

    private ComponentCoordinate component(String version) {
        return new ComponentCoordinate("com.example", "library", version);
    }
}

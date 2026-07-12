package com.vulncheck;

import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.nio.file.Path;

/** Coordinates mutation-point discovery, candidate generation, and evaluation. */
public class VulnerabilitiesFixer {

    private final List<Vulnerability> vulnerabilities;
    private final DependencyGraph dependencyGraph;
    private final EffectiveMavenModel effectiveMavenModel;
    private final MutationPointResolver mutationPointResolver;
    private final CandidateGenerator candidateGenerator;
    private final CandidateEvaluator candidateEvaluator;

    public VulnerabilitiesFixer(List<Vulnerability> vulnerabilities, DependencyGraph dependencyGraph) {
        this(
                vulnerabilities,
                dependencyGraph,
                EffectiveMavenModel.empty(),
                new RemediationMutationPointResolver(new EffectiveModelVersionOwnerResolver()),
                new SonatypeCandidateGenerator(),
                new BasicCandidateEvaluator()
        );
    }

    public VulnerabilitiesFixer(
            List<Vulnerability> vulnerabilities,
            DependencyGraph dependencyGraph,
            Path mavenProject
    ) {
        this(
                vulnerabilities,
                dependencyGraph,
                new MavenEffectiveModelBuilder().build(mavenProject),
                new RemediationMutationPointResolver(new EffectiveModelVersionOwnerResolver()),
                new SonatypeCandidateGenerator(),
                new BasicCandidateEvaluator()
        );
    }

    public VulnerabilitiesFixer(
            List<Vulnerability> vulnerabilities,
            DependencyGraph dependencyGraph,
            Path mavenProject,
            ComponentVersionRepository versionRepository
    ) {
        this(
                vulnerabilities,
                dependencyGraph,
                new MavenEffectiveModelBuilder().build(mavenProject),
                new RemediationMutationPointResolver(new EffectiveModelVersionOwnerResolver()),
                new CompositeCandidateGenerator(List.of(
                        new SonatypeCandidateGenerator(),
                        new RepositoryCandidateGenerator(versionRepository, new StableMavenVersionPolicy())
                )),
                new BasicCandidateEvaluator()
        );
    }

    public VulnerabilitiesFixer(
            List<Vulnerability> vulnerabilities,
            DependencyGraph dependencyGraph,
            EffectiveMavenModel effectiveMavenModel,
            MutationPointResolver mutationPointResolver,
            CandidateGenerator candidateGenerator,
            CandidateEvaluator candidateEvaluator
    ) {
        this.vulnerabilities = List.copyOf(Objects.requireNonNull(vulnerabilities, "vulnerabilities must not be null"));
        this.dependencyGraph = Objects.requireNonNull(dependencyGraph, "dependencyGraph must not be null");
        this.effectiveMavenModel = Objects.requireNonNull(effectiveMavenModel, "effectiveMavenModel must not be null");
        this.mutationPointResolver = Objects.requireNonNull(mutationPointResolver, "mutationPointResolver must not be null");
        this.candidateGenerator = Objects.requireNonNull(candidateGenerator, "candidateGenerator must not be null");
        this.candidateEvaluator = Objects.requireNonNull(candidateEvaluator, "candidateEvaluator must not be null");
    }

    /**
     * Returns candidates with an explicit replacement version that passed the
     * currently configured evaluator. Graph ancestry alone never becomes a fix.
     */
    public List<FixCandidate> findCandidates() {
        return findPatchCandidates().stream().map(PatchCandidate::candidate).toList();
    }

    public List<PatchCandidate> findPatchCandidates() {
        List<EvaluatedCandidate> accepted = new ArrayList<>();

        for (Vulnerability vulnerability : vulnerabilities) {
            RemediationCandidate remediation = vulnerability.getRemediationCandidate();

            mutationPointResolver.resolve(vulnerability, dependencyGraph, effectiveMavenModel).stream()
                    .flatMap(point -> candidateGenerator.generate(point, remediation, vulnerability).stream())
                    .map(candidate -> new EvaluatedCandidate(candidate, candidateEvaluator.evaluate(candidate)))
                    .filter(candidate -> candidate.evaluation().accepted())
                    .forEach(accepted::add);
        }

        return distinctAndSort(accepted);
    }

    private List<PatchCandidate> distinctAndSort(List<EvaluatedCandidate> candidates) {
        Map<String, EvaluatedCandidate> unique = new LinkedHashMap<>();
        candidates.stream()
                .sorted(Comparator
                        .comparingInt((EvaluatedCandidate candidate) -> candidate.evaluation().riskScore())
                        .thenComparingInt(candidate -> candidate.patchCandidate().recommendationPriority())
                        .thenComparing(candidate -> candidateKey(candidate.patchCandidate().candidate())))
                .forEach(candidate -> unique.putIfAbsent(candidateKey(candidate.patchCandidate().candidate()), candidate));

        return unique.values().stream()
                .map(EvaluatedCandidate::patchCandidate)
                .toList();
    }

    private String candidateKey(FixCandidate candidate) {
        DependencyNode node = candidate.node();
        ComponentCoordinate replacement = candidate.replacement().coordinate();
        return candidate.vulnerability().getId() + "|"
                + node.groupId() + ":" + node.artifactId() + ":" + node.version() + "|"
                + replacement.groupId() + ":" + replacement.artifactId() + ":" + replacement.version();
    }

    private record EvaluatedCandidate(PatchCandidate patchCandidate, CandidateEvaluation evaluation) {
    }
}

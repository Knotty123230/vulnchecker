package com.vulncheck;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Keeps Sonatype recommendations first and appends repository-discovered upgrades. */
public final class CompositeCandidateGenerator implements CandidateGenerator {

    private final List<CandidateGenerator> delegates;

    public CompositeCandidateGenerator(List<CandidateGenerator> delegates) {
        this.delegates = List.copyOf(delegates);
    }

    @Override
    public List<PatchCandidate> generate(
            MutationPoint mutationPoint,
            RemediationCandidate remediation,
            Vulnerability vulnerability
    ) {
        Map<String, PatchCandidate> unique = new LinkedHashMap<>();
        for (CandidateGenerator delegate : delegates) {
            for (PatchCandidate candidate : delegate.generate(mutationPoint, remediation, vulnerability)) {
                ComponentCoordinate replacement = candidate.candidate().replacement().coordinate();
                String key = replacement.groupId() + ":" + replacement.artifactId() + ":" + replacement.version();
                unique.putIfAbsent(key, candidate);
            }
        }
        return List.copyOf(unique.values());
    }
}

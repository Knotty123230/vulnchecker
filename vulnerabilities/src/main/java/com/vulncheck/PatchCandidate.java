package com.vulncheck;

/** Candidate before verification against a re-resolved dependency graph. */
public record PatchCandidate(MutationPoint mutationPoint, FixCandidate candidate, int recommendationPriority) {
    public PatchCandidate(MutationPoint mutationPoint, FixCandidate candidate) {
        this(mutationPoint, candidate, 0);
    }
}

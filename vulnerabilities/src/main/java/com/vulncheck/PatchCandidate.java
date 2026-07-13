package com.vulncheck;

import java.util.Objects;

/** Candidate before verification against a re-resolved dependency graph. */
public record PatchCandidate(MutationPoint mutationPoint, FixCandidate candidate, int recommendationPriority) {
    public PatchCandidate {
        Objects.requireNonNull(mutationPoint, "mutationPoint must not be null");
        Objects.requireNonNull(candidate, "candidate must not be null");
        Objects.requireNonNull(mutationPoint.type(), "mutation type must not be null");
        Objects.requireNonNull(mutationPoint.component(), "mutation component must not be null");
        Objects.requireNonNull(mutationPoint.component().version(), "current version must not be null");
        Objects.requireNonNull(candidate.replacement(), "replacement must not be null");
        Objects.requireNonNull(candidate.replacement().coordinate(), "replacement coordinate must not be null");
        Objects.requireNonNull(candidate.replacement().coordinate().version(), "replacement version must not be null");
    }

    public PatchCandidate(MutationPoint mutationPoint, FixCandidate candidate) {
        this(mutationPoint, candidate, 0);
    }
}

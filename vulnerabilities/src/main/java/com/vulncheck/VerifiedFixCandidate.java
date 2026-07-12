package com.vulncheck;

/** Holds the result once a future evaluator performs full Maven verification. */
public record VerifiedFixCandidate(PatchCandidate candidate, CandidateEvaluation evaluation) {
}

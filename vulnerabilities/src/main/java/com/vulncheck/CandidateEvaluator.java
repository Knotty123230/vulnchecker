package com.vulncheck;

public interface CandidateEvaluator {
    CandidateEvaluation evaluate(PatchCandidate candidate);
}

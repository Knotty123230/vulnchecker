package com.vulncheck;

/**
 * Minimal local validation. A production evaluator should re-resolve Maven,
 * calculate graph diff, verify alignment, then compile and run tests.
 */
public final class BasicCandidateEvaluator implements CandidateEvaluator {

    @Override
    public CandidateEvaluation evaluate(PatchCandidate patchCandidate) {
        FixCandidate candidate = patchCandidate.candidate();
        if (patchCandidate.mutationPoint().component().version()
                .equals(candidate.replacement().coordinate().version())) {
            return CandidateEvaluation.rejected("replacement version equals the resolved version");
        }

        int risk = switch (patchCandidate.mutationPoint().type()) {
            case UPDATE_PROPERTY, UPDATE_DIRECT_DEPENDENCY -> 0;
            case UPDATE_DEPENDENCY_MANAGEMENT -> 10;
            case UPDATE_IMPORTED_BOM -> 20;
            case UPDATE_PARENT_DEPENDENCY, UPDATE_PARENT_POM -> 30;
        };
        return CandidateEvaluation.accepted(risk);
    }
}

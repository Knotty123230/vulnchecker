package com.vulncheck;

import org.apache.maven.artifact.versioning.ComparableVersion;

/**
 * Minimal local validation. A production evaluator should re-resolve Maven,
 * calculate graph diff, verify alignment, then compile and run tests.
 */
public final class BasicCandidateEvaluator implements CandidateEvaluator {

    @Override
    public CandidateEvaluation evaluate(PatchCandidate patchCandidate) {
        FixCandidate candidate = patchCandidate.candidate();
        String currentVersion = patchCandidate.mutationPoint().component().version();
        String replacementVersion = candidate.replacement().coordinate().version();
        int comparison = new ComparableVersion(replacementVersion).compareTo(new ComparableVersion(currentVersion));
        if (comparison <= 0) {
            return CandidateEvaluation.rejected(comparison == 0
                    ? "replacement version equals the resolved version"
                    : "replacement would downgrade the resolved version");
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

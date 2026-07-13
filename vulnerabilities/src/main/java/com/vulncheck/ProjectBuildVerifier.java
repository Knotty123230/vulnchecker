package com.vulncheck;

import java.nio.file.Path;

@FunctionalInterface
public interface ProjectBuildVerifier {
    /** Captures any project state that must be compared before a mutation is applied. */
    default BuildVerificationResult prepare(Path projectPath, PatchCandidate candidate) {
        return BuildVerificationResult.success();
    }

    BuildVerificationResult verify(Path projectPath, PatchCandidate candidate);

    /** Advances the comparison baseline only after both build and security verification committed the patch. */
    default void patchCommitted(Path projectPath, PatchCandidate candidate) {
    }
}

package com.vulncheck;

import java.nio.file.Path;

@FunctionalInterface
public interface PatchSecurityVerifier {
    SecurityVerificationResult verify(Path projectPath, PatchCandidate candidate);

    static PatchSecurityVerifier accepting() {
        return (projectPath, candidate) -> SecurityVerificationResult.safeResult();
    }

    static PatchSecurityVerifier unconfigured() {
        return (projectPath, candidate) -> SecurityVerificationResult.unsafe(
                "security verifier is not configured"
        );
    }
}

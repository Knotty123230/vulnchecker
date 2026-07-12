package com.vulncheck;

import java.nio.file.Path;

@FunctionalInterface
public interface ProjectBuildVerifier {
    BuildVerificationResult verify(Path projectPath, PatchCandidate candidate);
}

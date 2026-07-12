package com.vulncheck;

public record AppliedPatch(PatchCandidate candidate, BuildVerificationResult verification) {
}

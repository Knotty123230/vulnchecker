package com.vulncheck;

public record BuildVerificationResult(boolean successful, int exitCode, String failure) {
    public static BuildVerificationResult success() {
        return new BuildVerificationResult(true, 0, null);
    }

    public static BuildVerificationResult failure(int exitCode, String failure) {
        return new BuildVerificationResult(false, exitCode, failure);
    }
}

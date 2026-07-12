package com.vulncheck;

public record SecurityVerificationResult(boolean safe, String failure) {
    public static SecurityVerificationResult safeResult() {
        return new SecurityVerificationResult(true, null);
    }

    public static SecurityVerificationResult unsafe(String failure) {
        return new SecurityVerificationResult(false, failure);
    }
}

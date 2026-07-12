package com.vulncheck;

public class MavenAnalysisException extends RuntimeException {
    public MavenAnalysisException(String message) {
        super(message);
    }

    public MavenAnalysisException(String message, Throwable cause) {
        super(message, cause);
    }
}

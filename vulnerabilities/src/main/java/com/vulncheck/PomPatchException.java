package com.vulncheck;

public class PomPatchException extends RuntimeException {
    public PomPatchException(String message) {
        super(message);
    }

    public PomPatchException(String message, Throwable cause) {
        super(message, cause);
    }
}

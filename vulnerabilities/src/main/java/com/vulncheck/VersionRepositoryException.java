package com.vulncheck;

public class VersionRepositoryException extends RuntimeException {
    public VersionRepositoryException(String message) {
        super(message);
    }

    public VersionRepositoryException(String message, Throwable cause) {
        super(message, cause);
    }
}

package com.vulncheck;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

/** Restores the exact original POM unless the patch is explicitly committed. */
public final class PomPatchTransaction implements AutoCloseable {

    private final Path pom;
    private final byte[] originalContent;
    private boolean committed;

    PomPatchTransaction(Path pom, byte[] originalContent) {
        this.pom = pom;
        this.originalContent = originalContent.clone();
    }

    public void commit() {
        committed = true;
    }

    public void rollback() {
        if (committed) {
            return;
        }
        try {
            Files.write(pom, originalContent);
            committed = true;
        } catch (IOException exception) {
            throw new PomPatchException("Unable to restore " + pom, exception);
        }
    }

    @Override
    public void close() {
        rollback();
    }
}

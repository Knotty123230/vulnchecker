package com.vulncheck;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.StandardCopyOption;

/** Restores the exact original POM unless the patch is explicitly committed. */
public final class PomPatchTransaction implements AutoCloseable {

    private final Path pom;
    private final byte[] originalContent;
    private final int mutationCount;
    private boolean committed;

    PomPatchTransaction(Path pom, byte[] originalContent, int mutationCount) {
        this.pom = pom;
        this.originalContent = originalContent.clone();
        this.mutationCount = mutationCount;
    }

    public int mutationCount() {
        return mutationCount;
    }

    public void commit() {
        committed = true;
    }

    public void rollback() {
        if (committed) {
            return;
        }
        Path temporary = null;
        try {
            temporary = Files.createTempFile(pom.getParent(), ".vulnchecker-rollback-", ".pom");
            Files.write(temporary, originalContent);
            try {
                Files.move(temporary, pom, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException ignored) {
                Files.move(temporary, pom, StandardCopyOption.REPLACE_EXISTING);
            }
            committed = true;
        } catch (IOException exception) {
            throw new PomPatchException("Unable to restore " + pom, exception);
        } finally {
            if (temporary != null) {
                try {
                    Files.deleteIfExists(temporary);
                } catch (IOException ignored) {
                }
            }
        }
    }

    @Override
    public void close() {
        rollback();
    }
}

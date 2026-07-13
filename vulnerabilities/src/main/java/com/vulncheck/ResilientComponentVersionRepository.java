package com.vulncheck;

import java.util.List;
import java.util.Objects;
import java.util.function.Consumer;

/** Keeps Sonatype candidates usable when an optional version catalog is temporarily unavailable. */
public final class ResilientComponentVersionRepository implements ComponentVersionRepository {

    private final ComponentVersionRepository delegate;
    private final Consumer<String> console;

    public ResilientComponentVersionRepository(
            ComponentVersionRepository delegate,
            Consumer<String> console
    ) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
        this.console = Objects.requireNonNull(console, "console must not be null");
    }

    @Override
    public List<String> findVersions(ComponentCoordinate component) {
        try {
            return delegate.findVersions(component);
        } catch (VersionRepositoryException exception) {
            console.accept("[VERSIONS] Unable to query " + component.groupId() + ":"
                    + component.artifactId() + ": " + exception.getMessage());
            return List.of();
        }
    }

    @Override
    public boolean isAvailable(ComponentCoordinate component, String extension) {
        try {
            return delegate.isAvailable(component, extension);
        } catch (VersionRepositoryException exception) {
            console.accept("[VERSIONS] Unable to verify " + component.groupId() + ":"
                    + component.artifactId() + ":" + component.version() + ": " + exception.getMessage());
            return false;
        }
    }
}

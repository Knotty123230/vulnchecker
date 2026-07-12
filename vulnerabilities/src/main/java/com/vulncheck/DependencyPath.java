package com.vulncheck;

import java.util.List;

/** Ordered path from the Maven project/root to a resolved component. */
public record DependencyPath(ComponentCoordinate component, List<ComponentCoordinate> path) {
    public DependencyPath {
        path = List.copyOf(path);
    }

    public ComponentCoordinate introducedBy() {
        return path.size() < 2 ? null : path.get(path.size() - 2);
    }
}

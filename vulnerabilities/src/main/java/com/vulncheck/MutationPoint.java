package com.vulncheck;

/** A concrete Maven-model location that may be changed, before a replacement version is chosen. */
public record MutationPoint(
        MutationType type,
        ComponentCoordinate component,
        DependencyNode resolvedNode,
        VersionOwner owner
) {
}

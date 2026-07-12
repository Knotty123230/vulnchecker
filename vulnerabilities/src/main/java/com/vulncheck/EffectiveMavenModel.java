package com.vulncheck;

import java.nio.file.Path;
import java.util.List;

/** Effective Maven data used separately for version ownership and dependency provenance. */
public record EffectiveMavenModel(
        Path projectPom,
        Path generatedEffectivePom,
        ComponentCoordinate project,
        List<ComponentCoordinate> importedBoms,
        List<VersionOwnerBinding> versionOwners,
        List<DependencyPath> dependencyPaths
) {
    public EffectiveMavenModel {
        importedBoms = List.copyOf(importedBoms);
        versionOwners = List.copyOf(versionOwners);
        dependencyPaths = List.copyOf(dependencyPaths);
    }

    public EffectiveMavenModel(List<VersionOwnerBinding> versionOwners) {
        this(null, null, null, List.of(), versionOwners, List.of());
    }

    public static EffectiveMavenModel empty() {
        return new EffectiveMavenModel(List.of());
    }

    public List<VersionOwner> ownersOf(ComponentCoordinate component) {
        return versionOwners.stream()
                .filter(binding -> binding.component().equals(component))
                .flatMap(binding -> binding.owners().stream())
                .distinct()
                .toList();
    }

    public List<DependencyPath> pathsTo(ComponentCoordinate component) {
        return dependencyPaths.stream()
                .filter(path -> path.component().equals(component))
                .toList();
    }

    /** Direct project dependencies found on paths to the component. */
    public List<ComponentCoordinate> nearestDirectDependenciesOf(ComponentCoordinate component) {
        return pathsTo(component).stream()
                .map(DependencyPath::path)
                .filter(path -> path.size() >= 2)
                .map(path -> path.get(1))
                .filter(direct -> !direct.equals(component))
                .distinct()
                .toList();
    }
}

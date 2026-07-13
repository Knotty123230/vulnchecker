package com.vulncheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/** Produces mutation points only from direct remediation, Sonatype parents, or an effective-model owner. */
public final class RemediationMutationPointResolver implements MutationPointResolver {

    private final VersionOwnerResolver versionOwnerResolver;

    public RemediationMutationPointResolver(VersionOwnerResolver versionOwnerResolver) {
        this.versionOwnerResolver = Objects.requireNonNull(versionOwnerResolver, "versionOwnerResolver must not be null");
    }

    @Override
    public List<MutationPoint> resolve(
            Vulnerability vulnerability,
            DependencyGraph graph,
            EffectiveMavenModel model
    ) {
        RemediationCandidate remediation = vulnerability.getRemediationCandidate();
        ComponentCoordinate vulnerable = new ComponentCoordinate(
                vulnerability.getGroupId(), vulnerability.getArtifactId(), vulnerability.getVersion()
        );
        List<DependencyNode> vulnerableNodes = findNodes(graph, vulnerable);
        List<MutationPoint> points = new ArrayList<>();
        List<VersionOwner> resolvedOwners = versionOwnerResolver.resolveOwners(vulnerable, model);

        if (model.projectPom() == null
                && remediation != null
                && remediation.directDependency()
                && resolvedOwners.isEmpty()) {
            vulnerableNodes.forEach(node -> points.add(new MutationPoint(
                    MutationType.UPDATE_DIRECT_DEPENDENCY, vulnerable, node,
                    new VersionOwner(VersionOwnerType.DIRECT_DEPENDENCY, vulnerable, null, null)
            )));
        }

        sonatypeParents(remediation).forEach(parentTarget -> findNodesByGa(graph, parentTarget).forEach(node -> points.add(
                new MutationPoint(
                        MutationType.UPDATE_PARENT_DEPENDENCY,
                        new ComponentCoordinate(node.groupId(), node.artifactId(), node.version()),
                        node,
                        new VersionOwner(VersionOwnerType.UNKNOWN, parentTarget, null, null)
                )
        )));

        resolvedOwners.forEach(owner -> {
            List<DependencyNode> ownerNodes = ownerTargetsVulnerableComponent(owner, vulnerable)
                    ? vulnerableNodes
                    : findNodes(graph, owner.coordinate());
            if (ownerNodes.isEmpty()) {
                DependencyNode vulnerableAnchor = vulnerableNodes.isEmpty() ? null : vulnerableNodes.getFirst();
                points.add(new MutationPoint(
                        toMutationType(owner.type()), owner.coordinate(), vulnerableAnchor, owner
                ));
            } else {
                ownerNodes.forEach(node -> points.add(
                        new MutationPoint(toMutationType(owner.type()), owner.coordinate(), node, owner)
                ));
            }
        });

        if (resolvedOwners.isEmpty()) {
            model.nearestDirectDependenciesOf(vulnerable).forEach(directDependency ->
                    findNodes(graph, directDependency).forEach(node -> points.add(new MutationPoint(
                            MutationType.UPDATE_PARENT_DEPENDENCY,
                            directDependency,
                            node,
                            new VersionOwner(VersionOwnerType.UNKNOWN, directDependency, null, model.projectPom())
                    )))
            );
        }

        // Fallback: if still no points, use the dependency tree to find who pulls this artifact
        // and create a mutation point to upgrade that parent instead of overriding
        if (model.projectPom() == null && points.isEmpty() && !vulnerableNodes.isEmpty()) {
            List<DependencyNode> parents = new ArrayList<>();
            graph.findParentNodes(vulnerableNodes).forEach(parents::add);
            // Filter to parents that are likely direct dependencies (have their own version declared)
            parents.stream()
                    .filter(parent -> parent.version() != null && !parent.version().isBlank())
                    .distinct()
                    .forEach(parent -> points.add(new MutationPoint(
                            MutationType.UPDATE_DIRECT_DEPENDENCY,
                            new ComponentCoordinate(parent.groupId(), parent.artifactId(), parent.version()),
                            parent,
                            new VersionOwner(VersionOwnerType.UNKNOWN,
                                    new ComponentCoordinate(parent.groupId(), parent.artifactId(), parent.version()),
                                    null, null)
                    )));
        }

        return points.stream().distinct().toList();
    }

    private boolean ownerTargetsVulnerableComponent(VersionOwner owner, ComponentCoordinate vulnerable) {
        return (owner.type() == VersionOwnerType.LOCAL_PROPERTY
                && sameComponent(owner.coordinate(), vulnerable))
                || owner.type() == VersionOwnerType.DEPENDENCY_MANAGEMENT
                || owner.type() == VersionOwnerType.DIRECT_DEPENDENCY;
    }

    private boolean sameComponent(ComponentCoordinate first, ComponentCoordinate second) {
        return first != null && second != null
                && first.groupId().equals(second.groupId())
                && first.artifactId().equals(second.artifactId());
    }

    private List<ComponentCoordinate> sonatypeParents(RemediationCandidate remediation) {
        if (remediation == null || remediation.parentCandidates() == null) {
            return List.of();
        }
        return remediation.parentCandidates().stream()
                .filter(Objects::nonNull)
                .filter(this::hasCoordinates)
                .distinct()
                .toList();
    }

    private List<DependencyNode> findNodes(DependencyGraph graph, ComponentCoordinate component) {
        return findNodesByGa(graph, component).stream()
                .filter(node -> component.version().equals(node.version()))
                .toList();
    }

    private List<DependencyNode> findNodesByGa(DependencyGraph graph, ComponentCoordinate component) {
        List<DependencyNode> nodes = new ArrayList<>();
        graph.findNodesByGroupIdAndArtifactId(component.groupId(), component.artifactId()).forEach(nodes::add);
        return nodes;
    }

    private boolean hasCoordinates(ComponentCoordinate coordinate) {
        return coordinate.groupId() != null && coordinate.artifactId() != null && coordinate.version() != null;
    }

    private MutationType toMutationType(VersionOwnerType type) {
        return switch (type) {
            case DIRECT_DEPENDENCY -> MutationType.UPDATE_DIRECT_DEPENDENCY;
            case LOCAL_PROPERTY -> MutationType.UPDATE_PROPERTY;
            case DEPENDENCY_MANAGEMENT -> MutationType.UPDATE_DEPENDENCY_MANAGEMENT;
            case IMPORTED_BOM -> MutationType.UPDATE_IMPORTED_BOM;
            case PARENT_POM -> MutationType.UPDATE_PARENT_POM;
            case UNKNOWN -> MutationType.UPDATE_PARENT_DEPENDENCY;
        };
    }
}

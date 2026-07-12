package com.vulncheck;

import java.util.List;

public record FixCandidate(Vulnerability vulnerability,
                           DependencyNode node,
                           ComponentFix replacement,
                           boolean directDependency,
                           List<ComponentFix> parentCandidates
) {


    public FixCandidate {
        if (vulnerability == null) {
            throw new IllegalArgumentException("vulnerability must not be null");
        }
        if (node == null) {
            throw new IllegalArgumentException("node must not be null");
        }
        if (replacement == null) {
            throw new IllegalArgumentException("replacement must not be null");
        }
    }


    public record ComponentFix(List<String> availableVersions, ComponentCoordinate coordinate) {
    }

}

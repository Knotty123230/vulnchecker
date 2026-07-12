package com.vulncheck;

import java.util.List;

public interface MutationPointResolver {
    List<MutationPoint> resolve(
            Vulnerability vulnerability,
            DependencyGraph graph,
            EffectiveMavenModel model
    );
}

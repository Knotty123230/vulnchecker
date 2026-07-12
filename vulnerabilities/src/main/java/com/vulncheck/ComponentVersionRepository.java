package com.vulncheck;

import java.util.List;

/** Port for any component-version catalog: Nexus, Artifactory, Central, or an internal service. */
@FunctionalInterface
public interface ComponentVersionRepository {
    List<String> findVersions(ComponentCoordinate component);

    static ComponentVersionRepository empty() {
        return component -> List.of();
    }
}

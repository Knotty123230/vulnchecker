package com.vulncheck;

import java.util.List;

/** Port for any component-version catalog: Nexus, Artifactory, Central, or an internal service. */
@FunctionalInterface
public interface ComponentVersionRepository {
    List<String> findVersions(ComponentCoordinate component);

    /** Confirms that the concrete artifact can be downloaded, not merely found in repository metadata. */
    default boolean isAvailable(ComponentCoordinate component, String extension) {
        return findVersions(component).contains(component.version());
    }

    static ComponentVersionRepository empty() {
        return component -> List.of();
    }
}

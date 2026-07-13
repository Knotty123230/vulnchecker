package com.vulncheck;

import java.util.List;

/** Resolves artifacts that are explicitly release-aligned by their published Maven POMs. */
@FunctionalInterface
public interface CompanionDependencyResolver {

    List<String> findCompanionArtifactIds(String groupId, String artifactId, String version);
}

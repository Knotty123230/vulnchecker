package com.vulncheck;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
record MavenDependencyTreeNode(
        String groupId,
        String artifactId,
        String version,
        List<MavenDependencyTreeNode> children
) {
}

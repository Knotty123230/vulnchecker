package com.vulncheck;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record MavenDependencyTreeDto(
        String artifactId,
        String groupId,
        String version,
        String type,
        String scope,
        List<MavenDependencyTreeDto> children
) {
}

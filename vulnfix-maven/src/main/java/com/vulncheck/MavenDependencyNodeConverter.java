package com.vulncheck;

import java.util.List;

public class MavenDependencyNodeConverter {
    public static DependencyNode convert(MavenDependencyTreeDto mavenDependencyTreeDto) {
        List<MavenDependencyTreeDto> children = mavenDependencyTreeDto.children() == null
                ? List.of()
                : mavenDependencyTreeDto.children();

        return new DependencyNode(
                mavenDependencyTreeDto.artifactId(),
                mavenDependencyTreeDto.groupId(),
                mavenDependencyTreeDto.version(),
                mavenDependencyTreeDto.scope(),
                children.stream().map(MavenDependencyNodeConverter::convert).toList()
        );
    }
}

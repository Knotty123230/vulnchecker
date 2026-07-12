package com.vulncheck;

import java.nio.file.Path;

@FunctionalInterface
public interface MavenCommandRunner {
    void generateModelAndDependencyTree(Path pom, Path effectivePomOutput, Path dependencyTreeOutput);
}

package com.vulncheck;

import java.util.List;

public interface VulnerabilitiesScanner {

    List<Vulnerability> scanDependencies(int projectId, DependencyNode dependencyNode);
}

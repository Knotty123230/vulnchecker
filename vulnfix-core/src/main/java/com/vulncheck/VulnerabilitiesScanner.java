package com.vulncheck;

import java.util.List;

public interface VulnerabilitiesScanner {

    List<Vulnerability> scanDependencies(String projectId, DependencyNode dependencyNode);
}

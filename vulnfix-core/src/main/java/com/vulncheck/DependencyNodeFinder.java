package com.vulncheck;

import java.nio.file.Path;

public interface DependencyNodeFinder {
    DependencyNode find(Path projectPath);
}

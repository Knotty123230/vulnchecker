package com.vulncheck;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

/**
 * Resolves the Maven home directory from system properties, environment variables, or PATH.
 */
final class MavenHomeResolver {

    private MavenHomeResolver() {
    }

    /**
     * Attempts to resolve Maven home in priority order:
     * 1. System property "maven.home"
     * 2. MAVEN_HOME environment variable
     * 3. M2_HOME environment variable
     * 4. Detect from 'mvn' executable on PATH
     *
     * @return Maven home path or null if not found
     */
    static String resolve() {
        String mavenHome = System.getProperty("maven.home");
        if (mavenHome != null) return mavenHome;

        mavenHome = System.getenv("MAVEN_HOME");
        if (mavenHome != null) return mavenHome;

        mavenHome = System.getenv("M2_HOME");
        if (mavenHome != null) return mavenHome;

        Path mvnPath = findMvnOnPath();
        if (mvnPath != null) {
            // mvn is typically at <maven-home>/bin/mvn
            return mvnPath.getParent().getParent().toString();
        }

        return null;
    }

    private static Path findMvnOnPath() {
        String pathEnv = System.getenv("PATH");
        if (pathEnv == null) return null;
        for (String dir : pathEnv.split(File.pathSeparator)) {
            Path candidate = Path.of(dir, "mvn");
            if (candidate.toFile().isFile() && candidate.toFile().canExecute()) {
                try {
                    return candidate.toRealPath();
                } catch (IOException e) {
                    return candidate;
                }
            }
        }
        return null;
    }
}

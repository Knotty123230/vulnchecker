package com.vulncheck;

import org.apache.maven.shared.invoker.DefaultInvoker;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Locale;

/** Selects the Maven installation provided by the operating system; project wrappers are not used. */
final class MavenExecutableResolver {

    private MavenExecutableResolver() {
    }

    static void configure(DefaultInvoker invoker) {
        Path executable = findOnPath();
        if (executable == null) {
            executable = findInConfiguredHome();
        }
        if (executable != null) {
            invoker.setMavenExecutable(executable.toFile());
        }
    }

    private static Path findOnPath() {
        String path = System.getenv("PATH");
        if (path == null || path.isBlank()) {
            return null;
        }
        for (String directory : path.split(java.util.regex.Pattern.quote(File.pathSeparator))) {
            if (directory.isBlank()) {
                continue;
            }
            for (String name : executableNames()) {
                Path executable = usableExecutable(Path.of(directory).resolve(name));
                if (executable != null) {
                    return executable;
                }
            }
        }
        return null;
    }

    private static Path findInConfiguredHome() {
        for (String home : List.of(
                System.getProperty("maven.home", ""),
                System.getenv().getOrDefault("MAVEN_HOME", ""),
                System.getenv().getOrDefault("M2_HOME", "")
        )) {
            if (home.isBlank()) {
                continue;
            }
            for (String name : executableNames()) {
                Path executable = usableExecutable(Path.of(home).resolve("bin").resolve(name));
                if (executable != null) {
                    return executable;
                }
            }
        }
        return null;
    }

    private static List<String> executableNames() {
        return isWindows() ? List.of("mvn.cmd", "mvn.bat", "mvn.exe") : List.of("mvn");
    }

    private static Path usableExecutable(Path candidate) {
        if (!Files.isRegularFile(candidate) || (!isWindows() && !Files.isExecutable(candidate))) {
            return null;
        }
        try {
            return candidate.toRealPath();
        } catch (IOException ignored) {
            return candidate.toAbsolutePath().normalize();
        }
    }

    private static boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(Locale.ROOT).contains("win");
    }
}

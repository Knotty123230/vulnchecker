package com.vulncheck;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

public class MavenDependencyNodeFinder implements DependencyNodeFinder {


    private static final String DEPENDENCY_TREE_GOAL =
            "org.apache.maven.plugins:maven-dependency-plugin:3.11.0:tree";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public DependencyNode find(Path projectPath) {
        Path normalizedPath = projectPath.toAbsolutePath().normalize();
        Path pom = Files.isDirectory(normalizedPath) ? normalizedPath.resolve("pom.xml") : normalizedPath;

        if (!Files.isRegularFile(pom)) {
            IO.println("No pom.xml found at: %s".formatted(pom));
            return null;
        }

        Path depTree = pom.getParent().resolve("target/dependency-tree.json");

        try {
            Files.createDirectories(depTree.getParent());
            Files.deleteIfExists(depTree);
        } catch (IOException e) {
            IO.println("Error occurred while preparing dependency tree output file.");
            e.printStackTrace();
            return null;
        }

        List<String> command = new ArrayList<>();
        command.add(mavenExecutable());
        command.add("--batch-mode");
        command.add("--non-recursive");
        command.add("--file");
        command.add(pom.toString());
        command.add(DEPENDENCY_TREE_GOAL);
        command.add("-DoutputFile=" + depTree.toAbsolutePath());
        command.add("-DoutputType=json");
        command.add("-Dverbose=true");
        ProcessBuilder processBuilder = new ProcessBuilder(command);
        processBuilder.directory(pom.getParent().toFile());
        processBuilder.inheritIO();

        processBuilder.redirectErrorStream(true);
        try {
            Process process = processBuilder.start();
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                IO.println("Maven dependency tree generation failed with exit code: %d".formatted(exitCode));
                return null;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            IO.println("Maven process was interrupted.");
            e.printStackTrace();
            return null;
        } catch (IOException e) {
            IO.println("Error occurred while executing Maven process.");
            e.printStackTrace();
            return null;
        }


        if (!Files.exists(depTree)) {
           IO.println("No dependency tree found in the project path: %s".formatted(normalizedPath));
           return null;
        }

        var json = depTree.toFile();
        IO.println("Dependency tree found at: %s".formatted(json.getAbsolutePath()));
        IO.println("Parsing dependency tree...");

        try {
            MavenDependencyTreeDto mavenDependencyTreeDto = objectMapper.readValue(json, MavenDependencyTreeDto.class);
            IO.println("Dependency tree parsed successfully.");
            return MavenDependencyNodeConverter.convert(mavenDependencyTreeDto);
        } catch (IOException e) {
            IO.println("Error occurred while parsing dependency tree.");
            e.printStackTrace();
            return null;
        }
    }

    private String mavenExecutable() {
        return isWindows() ? "mvn.cmd" : "mvn";
    }

    private boolean isWindows() {
        return System.getProperty("os.name", "").toLowerCase(java.util.Locale.ROOT).contains("win");
    }
}

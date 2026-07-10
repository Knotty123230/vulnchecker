package com.vulncheck;

import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

public class MavenDependencyNodeFinder implements DependencyNodeFinder {


    private static final String DEPENDENCY_TREE_GOAL = "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public DependencyNode find(Path projectPath) {
        Path absolutePath = projectPath.toAbsolutePath();
        Path normalizedPath = absolutePath.normalize();

        var pom = normalizedPath.resolve("pom.xml");

        if (!Files.exists(pom)) {
            IO.println("No pom.xml found in the project path: %s".formatted(normalizedPath));
            return null;
        }

        File pomFile = pom.toFile();
        Path depTree = normalizedPath.resolve("target/dependency-tree.json");

        try {
            Files.createDirectories(depTree.getParent());
            Files.deleteIfExists(depTree);
        } catch (IOException e) {
            IO.println("Error occurred while preparing dependency tree output file.");
            e.printStackTrace();
            return null;
        }

        ProcessBuilder processBuilder = new ProcessBuilder(
                "mvn",
                "-N",
                DEPENDENCY_TREE_GOAL,
                "-DoutputFile=%s".formatted(depTree),
                "-DoutputType=json"
        );
        processBuilder.directory(pomFile.getParentFile());
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
}

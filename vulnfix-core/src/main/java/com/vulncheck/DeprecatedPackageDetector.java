package com.vulncheck;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detects deprecated packages in pom.xml that should be migrated.
 * Primary focus: javax → jakarta migration (Java EE → Jakarta EE).
 */
public final class DeprecatedPackageDetector {

    public record DeprecatedDependency(
            String groupId,
            String artifactId,
            String version,
            String replacementGroupId,
            String replacementArtifactId,
            String reason
    ) {}

    private static final List<MigrationRule> MIGRATION_RULES = List.of(
            // javax → jakarta
            new MigrationRule("javax.xml.bind", "jaxb-api", "jakarta.xml.bind", "jakarta.xml.bind-api", "Java EE → Jakarta EE migration"),
            new MigrationRule("javax.persistence", "javax.persistence-api", "jakarta.persistence", "jakarta.persistence-api", "Java EE → Jakarta EE migration"),
            new MigrationRule("javax.servlet", "javax.servlet-api", "jakarta.servlet", "jakarta.servlet-api", "Java EE → Jakarta EE migration"),
            new MigrationRule("javax.validation", "validation-api", "jakarta.validation", "jakarta.validation-api", "Java EE → Jakarta EE migration"),
            new MigrationRule("javax.annotation", "javax.annotation-api", "jakarta.annotation", "jakarta.annotation-api", "Java EE → Jakarta EE migration"),
            new MigrationRule("javax.inject", "javax.inject", "jakarta.inject", "jakarta.inject-api", "Java EE → Jakarta EE migration"),
            new MigrationRule("javax.activation", "javax.activation-api", "jakarta.activation", "jakarta.activation-api", "Java EE → Jakarta EE migration"),
            new MigrationRule("javax.mail", "javax.mail-api", "jakarta.mail", "jakarta.mail-api", "Java EE → Jakarta EE migration"),
            new MigrationRule("javax.ws.rs", "javax.ws.rs-api", "jakarta.ws.rs", "jakarta.ws.rs-api", "Java EE → Jakarta EE migration"),
            new MigrationRule("javax.json", "javax.json-api", "jakarta.json", "jakarta.json-api", "Java EE → Jakarta EE migration"),
            new MigrationRule("javax.transaction", "javax.transaction-api", "jakarta.transaction", "jakarta.transaction-api", "Java EE → Jakarta EE migration"),
            // Other deprecated
            new MigrationRule("junit", "junit", "org.junit.jupiter", "junit-jupiter", "JUnit 4 → JUnit 5 migration"),
            new MigrationRule("log4j", "log4j", "org.apache.logging.log4j", "log4j-core", "Log4j 1.x → Log4j 2.x (EOL)")
    );

    public List<DeprecatedDependency> detect(Path projectPath) {
        Path pom = projectPath.toAbsolutePath().normalize();
        if (Files.isDirectory(pom)) pom = pom.resolve("pom.xml");
        if (!Files.isRegularFile(pom)) return List.of();

        try {
            String content = Files.readString(pom, StandardCharsets.UTF_8);
            return findDeprecated(content);
        } catch (IOException e) {
            return List.of();
        }
    }

    public List<DeprecatedDependency> detectInTree(DependencyNode root) {
        if (root == null) return List.of();
        List<DeprecatedDependency> found = new ArrayList<>();
        detectRecursive(root, found);
        return found;
    }

    private void detectRecursive(DependencyNode node, List<DeprecatedDependency> found) {
        for (MigrationRule rule : MIGRATION_RULES) {
            if (rule.oldGroupId.equals(node.groupId()) && rule.oldArtifactId.equals(node.artifactId())) {
                found.add(new DeprecatedDependency(
                        node.groupId(), node.artifactId(), node.version(),
                        rule.newGroupId, rule.newArtifactId, rule.reason
                ));
            }
        }
        if (node.children() != null) {
            for (DependencyNode child : node.children()) {
                if (child != null) detectRecursive(child, found);
            }
        }
    }

    private List<DeprecatedDependency> findDeprecated(String content) {
        Pattern blockPattern = Pattern.compile("<dependency>(.*?)</dependency>", Pattern.DOTALL);
        List<DeprecatedDependency> found = new ArrayList<>();

        Matcher blockMatcher = blockPattern.matcher(content);
        while (blockMatcher.find()) {
            String block = blockMatcher.group(1);
            String groupId = extractTag(block, "groupId");
            String artifactId = extractTag(block, "artifactId");
            String version = extractTag(block, "version");

            if (groupId == null || artifactId == null) continue;

            for (MigrationRule rule : MIGRATION_RULES) {
                if (rule.oldGroupId.equals(groupId) && rule.oldArtifactId.equals(artifactId)) {
                    found.add(new DeprecatedDependency(
                            groupId, artifactId, version,
                            rule.newGroupId, rule.newArtifactId, rule.reason
                    ));
                }
            }
        }
        return found;
    }

    private String extractTag(String block, String tag) {
        Pattern p = Pattern.compile("<" + tag + ">\\s*([^<]+)\\s*</" + tag + ">");
        Matcher m = p.matcher(block);
        return m.find() ? m.group(1).trim() : null;
    }

    private record MigrationRule(String oldGroupId, String oldArtifactId, String newGroupId, String newArtifactId, String reason) {}
}

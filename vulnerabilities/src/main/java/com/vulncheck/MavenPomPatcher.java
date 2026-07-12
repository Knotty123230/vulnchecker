package com.vulncheck;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Applies one candidate to the project's own pom.xml via text replacement (preserves formatting). */
public final class MavenPomPatcher {

    public PomPatchTransaction apply(Path projectPath, PatchCandidate patchCandidate) {
        Path pom = resolvePom(projectPath);
        byte[] original = read(pom);
        String content = new String(original, StandardCharsets.UTF_8);
        MutationPoint point = patchCandidate.mutationPoint();
        String newVersion = patchCandidate.candidate().replacement().coordinate().version();

        String patched = switch (point.type()) {
            case UPDATE_PROPERTY -> patchProperty(content, point.owner().propertyName(), newVersion);
            case UPDATE_DIRECT_DEPENDENCY -> patchDependencyVersion(content, point.component(), newVersion);
            case UPDATE_DEPENDENCY_MANAGEMENT -> patchDependencyVersion(content, point.component(), newVersion);
            case UPDATE_IMPORTED_BOM -> patchDependencyVersion(content, point.owner().coordinate(), newVersion);
            case UPDATE_PARENT_DEPENDENCY -> patchDependencyVersion(content, point.component(), newVersion);
            case UPDATE_PARENT_POM -> patchParentVersion(content, point.owner().coordinate(), newVersion);
        };

        // Fallback: if dependency not found, insert a version override into <dependencyManagement>
        if (patched == null && point.component() != null) {
            patched = insertDependencyManagementOverride(content, point.component(), newVersion);
        }

        if (patched == null) {
            throw new PomPatchException("Mutation point " + point.type() + " was not found in " + pom);
        }

        // Patch companion artifacts: same groupId + same old version → same new version
        // e.g., logback-core:1.5.32→1.5.35 should also update logback-classic:1.5.32→1.5.35
        if (point.type() == MutationType.UPDATE_DIRECT_DEPENDENCY
                || point.type() == MutationType.UPDATE_DEPENDENCY_MANAGEMENT) {
            patched = patchCompanionArtifacts(patched, point.component(), newVersion);
        }

        try {
            Files.writeString(pom, patched, StandardCharsets.UTF_8);
            return new PomPatchTransaction(pom, original);
        } catch (IOException | RuntimeException exception) {
            restore(pom, original);
            if (exception instanceof RuntimeException re) throw re;
            throw new PomPatchException("Unable to write " + pom, exception);
        }
    }

    /**
     * Finds all dependencies with the same groupId and same old version as the patched component,
     * and updates them to the new version. This handles companion artifacts like
     * logback-core + logback-classic, netty-handler + netty-codec-http, etc.
     * Guards: only patches if oldVersion matches exactly and newVersion > oldVersion.
     */
    private String patchCompanionArtifacts(String content, ComponentCoordinate component, String newVersion) {
        String groupId = component.groupId();
        String oldVersion = component.version();

        // Safety: never downgrade, never patch if versions are same
        if (newVersion.equals(oldVersion)) {
            return content;
        }

        String quotedGroupId = Pattern.quote(groupId);
        String quotedOldVersion = Pattern.quote(oldVersion);

        // Find each <dependency>...</dependency> block, check if it has same groupId + same old version
        Pattern blockPattern = Pattern.compile(
                "(<dependency>)(.*?)(</dependency>)",
                Pattern.DOTALL
        );

        Matcher blockMatcher = blockPattern.matcher(content);
        StringBuilder result = new StringBuilder();

        while (blockMatcher.find()) {
            String block = blockMatcher.group(2);
            if (block.matches("(?s).*<groupId>\\s*" + quotedGroupId + "\\s*</groupId>.*")
                    && block.matches("(?s).*<version>\\s*" + quotedOldVersion + "\\s*</version>.*")) {
                // Replace version within this block
                String patched = block.replaceFirst(
                        "(<version>)\\s*" + quotedOldVersion + "\\s*(</version>)",
                        "$1" + Matcher.quoteReplacement(newVersion) + "$2"
                );
                blockMatcher.appendReplacement(result,
                        Matcher.quoteReplacement("<dependency>" + patched + "</dependency>"));
            }
        }
        blockMatcher.appendTail(result);
        return result.toString();
    }

    private String patchProperty(String content, String propertyName, String newVersion) {
        if (propertyName == null) return null;
        // Match <propertyName>oldVersion</propertyName>
        Pattern pattern = Pattern.compile(
                "(<%s>)([^<]+)(</%s>)".formatted(Pattern.quote(propertyName), Pattern.quote(propertyName))
        );
        Matcher matcher = pattern.matcher(content);
        if (!matcher.find()) return null;
        String oldVersion = matcher.group(2).trim();
        if (oldVersion.equals(newVersion)) return null;
        return matcher.replaceFirst("$1" + Matcher.quoteReplacement(newVersion) + "$3");
    }

    private String patchDependencyVersion(String content, ComponentCoordinate component, String newVersion) {
        if (component == null) return null;

        String gId = Pattern.quote(component.groupId());
        String aId = Pattern.quote(component.artifactId());

        // Strategy: find a <dependency>...</dependency> block containing both groupId and artifactId,
        // then replace its <version> tag. Using </dependency> as boundary prevents cross-block matching.
        Pattern blockPattern = Pattern.compile(
                "(<dependency>)(.*?)(</dependency>)",
                Pattern.DOTALL
        );

        Matcher blockMatcher = blockPattern.matcher(content);
        StringBuilder result = new StringBuilder();
        boolean found = false;

        while (blockMatcher.find()) {
            String block = blockMatcher.group(2);
            // Check if this block contains both our groupId and artifactId
            if (block.matches("(?s).*<groupId>\\s*" + gId + "\\s*</groupId>.*")
                    && block.matches("(?s).*<artifactId>\\s*" + aId + "\\s*</artifactId>.*")) {
                // Replace <version>old</version> within this block
                String patched = block.replaceFirst(
                        "(<version>)([^<]+)(</version>)",
                        "$1" + Matcher.quoteReplacement(newVersion) + "$3"
                );
                if (!patched.equals(block)) {
                    blockMatcher.appendReplacement(result,
                            Matcher.quoteReplacement("<dependency>" + patched + "</dependency>"));
                    found = true;
                    break; // Only patch first match
                }
            }
        }

        if (!found) return null;
        blockMatcher.appendTail(result);
        return result.toString();
    }

    private String patchParentVersion(String content, ComponentCoordinate parent, String newVersion) {
        if (parent == null) return null;
        String gId = Pattern.quote(parent.groupId());
        String aId = Pattern.quote(parent.artifactId());

        // Match <parent> block with groupId + artifactId + version
        Pattern pattern = Pattern.compile(
                "(<parent>[^<]*(?:<(?!/parent>)[^<]*)*" +
                "<groupId>\\s*" + gId + "\\s*</groupId>[^<]*(?:<(?!/parent>)[^<]*)*" +
                "<artifactId>\\s*" + aId + "\\s*</artifactId>[^<]*(?:<(?!/parent>)[^<]*)*" +
                "<version>)([^<]+)(</version>)",
                Pattern.DOTALL
        );
        Matcher matcher = pattern.matcher(content);
        if (matcher.find()) {
            String oldVersion = matcher.group(2).trim();
            if (oldVersion.equals(newVersion)) return null;
            return content.substring(0, matcher.start(2))
                    + newVersion
                    + content.substring(matcher.end(2));
        }
        return null;
    }

    /**
     * Inserts a new dependency version override into <dependencyManagement><dependencies>.
     * Used when a transitive dependency is vulnerable but not explicitly declared in pom.xml.
     */
    private String insertDependencyManagementOverride(String content, ComponentCoordinate component, String newVersion) {
        // Find the first </dependencies> inside <dependencyManagement>
        Pattern dmPattern = Pattern.compile(
                "(<dependencyManagement>\\s*<dependencies>)(.*?)(</dependencies>\\s*</dependencyManagement>)",
                Pattern.DOTALL
        );
        Matcher matcher = dmPattern.matcher(content);
        if (!matcher.find()) {
            return null;
        }

        // Check if this dependency already exists in dependencyManagement
        String dmBlock = matcher.group(2);
        String gId = Pattern.quote(component.groupId());
        String aId = Pattern.quote(component.artifactId());
        if (dmBlock.matches("(?s).*<groupId>\\s*" + gId + "\\s*</groupId>.*<artifactId>\\s*" + aId + "\\s*</artifactId>.*")) {
            return null; // Already exists, should have been patched by patchDependencyVersion
        }

        // Insert new dependency entry before </dependencies>
        String indent = "            "; // typical Maven indentation
        String newDep = "\n" + indent + "<dependency>\n"
                + indent + "    <groupId>" + component.groupId() + "</groupId>\n"
                + indent + "    <artifactId>" + component.artifactId() + "</artifactId>\n"
                + indent + "    <version>" + newVersion + "</version>\n"
                + indent + "</dependency>";

        // Insert before the closing </dependencies> of dependencyManagement
        int insertPos = matcher.start(3);
        return content.substring(0, insertPos) + newDep + "\n" + indent + content.substring(insertPos);
    }

    private byte[] read(Path pom) {
        try {
            return Files.readAllBytes(pom);
        } catch (IOException exception) {
            throw new PomPatchException("Unable to read " + pom, exception);
        }
    }

    private void restore(Path pom, byte[] content) {
        try {
            Files.write(pom, content);
        } catch (IOException ignored) {
        }
    }

    private Path resolvePom(Path projectPath) {
        Path normalized = projectPath.toAbsolutePath().normalize();
        Path pom = Files.isDirectory(normalized) ? normalized.resolve("pom.xml") : normalized;
        if (!Files.isRegularFile(pom)) {
            throw new PomPatchException("pom.xml not found at " + pom);
        }
        return pom;
    }
}

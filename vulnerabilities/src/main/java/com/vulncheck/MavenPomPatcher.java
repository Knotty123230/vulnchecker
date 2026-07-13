package com.vulncheck;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Applies one candidate to the project's own pom.xml via text replacement (preserves formatting). */
public final class MavenPomPatcher {

    private final PomDependencyFetcher pomFetcher;

    public MavenPomPatcher() {
        this(null);
    }

    public MavenPomPatcher(PomDependencyFetcher pomFetcher) {
        this.pomFetcher = pomFetcher;
    }

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

        // Patch companion artifacts: always check for companions after any version change
        if (point.component() != null) {
            patched = patchCompanionArtifacts(patched, point.component(), newVersion);
        }

        // Also companion-patch the actual vulnerable artifact if different from mutation point
        Vulnerability vulnerability = patchCandidate.candidate().vulnerability();
        if (vulnerability != null) {
            ComponentCoordinate vulnerableCoord = new ComponentCoordinate(
                    vulnerability.getGroupId(), vulnerability.getArtifactId(), vulnerability.getVersion()
            );
            // Directly patch the vulnerable component if it exists in pom
            // (handles case where BOM was bumped but explicit override still has old version)
            String remediationVersion = patchCandidate.candidate().replacement().coordinate().version();
            if (remediationVersion != null) {
                String afterDirectPatch = patchDependencyVersion(patched, vulnerableCoord, remediationVersion);
                if (afterDirectPatch != null) {
                    patched = afterDirectPatch;
                }
            }
            // Companion for the vulnerable artifact's group
            if (!vulnerableCoord.groupId().equals(point.component().groupId())
                    || !vulnerableCoord.artifactId().equals(point.component().artifactId())) {
                patched = patchCompanionArtifacts(patched, vulnerableCoord, remediationVersion != null ? remediationVersion : newVersion);
            }
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
     * Patches companion artifacts that must share the same version.
     *
     * When Nexus POM fetcher is available: downloads the artifact's POM and finds
     * all siblings that use ${project.version} — those must be updated to the same version.
     *
     * Fallback: pattern-based — any artifact with same groupId and same old version.
     */
    private String patchCompanionArtifacts(String content, ComponentCoordinate component, String newVersion) {
        String groupId = component.groupId();
        String oldVersion = component.version();

        if (newVersion.equals(oldVersion)) return content;

        // Get companions: either from Nexus POM or by pattern
        java.util.Set<String> companionArtifactIds = new java.util.LinkedHashSet<>();

        if (pomFetcher != null) {
            // Nexus-based: precise companion discovery via parent modules
            pomFetcher.findCompanionArtifactIds(groupId, component.artifactId(), newVersion)
                    .forEach(companionArtifactIds::add);
        }

        // Determine which mode to use for matching
        boolean useNexusMode = !companionArtifactIds.isEmpty();

        // Find each <dependency>...</dependency> block
        Pattern blockPattern = Pattern.compile(
                "(<dependency>)(.*?)(</dependency>)",
                Pattern.DOTALL
        );
        Matcher blockMatcher = blockPattern.matcher(content);
        StringBuilder result = new StringBuilder();
        String quotedGroupId = Pattern.quote(groupId);
        String quotedOldVersion = Pattern.quote(oldVersion);

        while (blockMatcher.find()) {
            String block = blockMatcher.group(2);

            // Must be same groupId
            if (!block.matches("(?s).*<groupId>\\s*" + quotedGroupId + "\\s*</groupId>.*")) {
                continue;
            }

            boolean isCompanion;
            if (useNexusMode) {
                // Nexus mode: only update known companions
                isCompanion = companionArtifactIds.stream().anyMatch(aid ->
                        block.matches("(?s).*<artifactId>\\s*" + Pattern.quote(aid) + "\\s*</artifactId>.*"));
            } else {
                // Pattern mode: same groupId + version with same major.minor prefix
                // This handles cases where one sibling was already bumped (e.g., 11.0.23)
                // but should still be aligned to 11.0.24
                java.util.regex.Matcher vMatcher = java.util.regex.Pattern
                        .compile("<version>([^<]+)</version>").matcher(block);
                if (vMatcher.find()) {
                    String blockVersion = vMatcher.group(1).trim();
                    isCompanion = sameMajorMinor(blockVersion, oldVersion);
                } else {
                    isCompanion = false;
                }
            }

            if (!isCompanion) continue;

            // Check for downgrade protection
            java.util.regex.Matcher vMatcher = java.util.regex.Pattern
                    .compile("<version>([^<]+)</version>").matcher(block);
            if (vMatcher.find()) {
                String existing = vMatcher.group(1).trim();
                if (!existing.equals(newVersion)) {
                    try {
                        org.apache.maven.artifact.versioning.ComparableVersion ev =
                                new org.apache.maven.artifact.versioning.ComparableVersion(existing);
                        org.apache.maven.artifact.versioning.ComparableVersion nv =
                                new org.apache.maven.artifact.versioning.ComparableVersion(newVersion);
                        if (nv.compareTo(ev) < 0) continue; // never downgrade
                    } catch (Exception ignored) {}
                }
            }

            String patched = block.replaceFirst(
                    "(<version>)\\s*[^<]+\\s*(</version>)",
                    "$1" + Matcher.quoteReplacement(newVersion) + "$2"
            );
            blockMatcher.appendReplacement(result,
                    Matcher.quoteReplacement("<dependency>" + patched + "</dependency>"));
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

        // Strategy: find ALL <dependency>...</dependency> blocks containing both groupId and artifactId,
        // and replace their <version> tag. This ensures dependencyManagement AND dependencies stay in sync.
        Pattern blockPattern = Pattern.compile(
                "(<dependency>)(.*?)(</dependency>)",
                Pattern.DOTALL
        );

        Matcher blockMatcher = blockPattern.matcher(content);
        StringBuilder result = new StringBuilder();
        boolean found = false;

        while (blockMatcher.find()) {
            String block = blockMatcher.group(2);
            if (block.matches("(?s).*<groupId>\\s*" + gId + "\\s*</groupId>.*")
                    && block.matches("(?s).*<artifactId>\\s*" + aId + "\\s*</artifactId>.*")) {

                // Extract current version in this block
                java.util.regex.Matcher versionMatcher = java.util.regex.Pattern
                        .compile("<version>([^<]+)</version>")
                        .matcher(block);
                if (versionMatcher.find()) {
                    String existingVersion = versionMatcher.group(1).trim();
                    // Never downgrade — skip if existing is already newer
                    if (!existingVersion.equals(newVersion)) {
                        org.apache.maven.artifact.versioning.ComparableVersion existing =
                                new org.apache.maven.artifact.versioning.ComparableVersion(existingVersion);
                        org.apache.maven.artifact.versioning.ComparableVersion proposed =
                                new org.apache.maven.artifact.versioning.ComparableVersion(newVersion);
                        if (proposed.compareTo(existing) < 0) {
                            continue; // skip downgrade
                        }
                    }
                }

                String patched = block.replaceFirst(
                        "(<version>)([^<]+)(</version>)",
                        "$1" + Matcher.quoteReplacement(newVersion) + "$3"
                );
                if (!patched.equals(block)) {
                    blockMatcher.appendReplacement(result,
                            Matcher.quoteReplacement("<dependency>" + patched + "</dependency>"));
                    found = true;
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
     * Does NOT insert if the artifact already exists anywhere in the pom.
     */
    private String insertDependencyManagementOverride(String content, ComponentCoordinate component, String newVersion) {
        String gId = Pattern.quote(component.groupId());
        String aId = Pattern.quote(component.artifactId());

        // Check if this dependency already exists ANYWHERE in the pom (dependencyManagement or dependencies)
        Pattern existsPattern = Pattern.compile(
                "<dependency>.*?<groupId>\\s*" + gId + "\\s*</groupId>.*?<artifactId>\\s*" + aId + "\\s*</artifactId>.*?</dependency>",
                Pattern.DOTALL
        );
        if (existsPattern.matcher(content).find()) {
            return null; // Already declared somewhere — patchDependencyVersion should handle it
        }

        // Find the </dependencies> inside <dependencyManagement>
        Pattern dmPattern = Pattern.compile(
                "(<dependencyManagement>\\s*<dependencies>)(.*?)(</dependencies>\\s*</dependencyManagement>)",
                Pattern.DOTALL
        );
        Matcher matcher = dmPattern.matcher(content);
        if (!matcher.find()) {
            return null;
        }

        // Insert new dependency entry before </dependencies>
        String indent = "            ";
        String newDep = "\n" + indent + "<dependency>\n"
                + indent + "    <groupId>" + component.groupId() + "</groupId>\n"
                + indent + "    <artifactId>" + component.artifactId() + "</artifactId>\n"
                + indent + "    <version>" + newVersion + "</version>\n"
                + indent + "</dependency>";

        int insertPos = matcher.start(3);
        return content.substring(0, insertPos) + newDep + "\n" + indent + content.substring(insertPos);
    }

    private boolean sameMajorMinor(String v1, String v2) {
        if (v1 == null || v2 == null) return false;
        String prefix1 = majorMinorPrefix(v1);
        String prefix2 = majorMinorPrefix(v2);
        return prefix1.equals(prefix2);
    }

    private String majorMinorPrefix(String version) {
        int firstDot = version.indexOf('.');
        if (firstDot < 0) return version;
        int secondDot = version.indexOf('.', firstDot + 1);
        return secondDot > 0 ? version.substring(0, secondDot) : version;
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

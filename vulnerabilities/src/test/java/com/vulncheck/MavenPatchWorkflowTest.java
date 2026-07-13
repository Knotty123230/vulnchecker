package com.vulncheck;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MavenPatchWorkflowTest {

    @TempDir
    Path project;

    @Test
    void commitsPatchWhenMavenVerificationSucceeds() throws IOException {
        Files.writeString(project.resolve("pom.xml"), pomWithDependency("1.0.0"));
        PatchCandidate candidate = directCandidate("1.0.0", "1.1.0");
        List<String> console = new ArrayList<>();
        ProjectBuildVerifier verifier = (path, ignored) -> {
            try {
                assertTrue(Files.readString(path.resolve("pom.xml")).contains("1.1.0"));
                return BuildVerificationResult.success();
            } catch (IOException exception) {
                throw new RuntimeException(exception);
            }
        };

        List<AppliedPatch> applied = new MavenPatchWorkflow(
                new MavenPomPatcher(), verifier, PatchSecurityVerifier.accepting(), console::add
        ).applyRecommendedPatches(project, List.of(candidate));

        assertEquals(1, applied.size());
        assertTrue(Files.readString(project.resolve("pom.xml")).contains("1.1.0"));
        assertTrue(console.stream().anyMatch(line -> line.contains("patch committed")));
    }

    @Test
    void capturesBuildBaselineBeforeMutatingPomAndAdvancesItOnlyAfterCommit() throws IOException {
        Files.writeString(project.resolve("pom.xml"), pomWithDependency("1.0.0"));
        PatchCandidate candidate = directCandidate("1.0.0", "1.1.0");
        AtomicBoolean prepared = new AtomicBoolean();
        AtomicBoolean committed = new AtomicBoolean();
        ProjectBuildVerifier verifier = new ProjectBuildVerifier() {
            @Override
            public BuildVerificationResult prepare(Path path, PatchCandidate ignored) {
                try {
                    assertTrue(Files.readString(path.resolve("pom.xml")).contains("1.0.0"));
                    prepared.set(true);
                    return BuildVerificationResult.success();
                } catch (IOException exception) {
                    throw new RuntimeException(exception);
                }
            }

            @Override
            public BuildVerificationResult verify(Path path, PatchCandidate ignored) {
                assertTrue(prepared.get());
                return BuildVerificationResult.success();
            }

            @Override
            public void patchCommitted(Path path, PatchCandidate ignored) {
                committed.set(true);
            }
        };

        new MavenPatchWorkflow(
                new MavenPomPatcher(), verifier, PatchSecurityVerifier.accepting(), ignored -> { }
        ).applyRecommendedPatches(project, List.of(candidate));

        assertTrue(prepared.get());
        assertTrue(committed.get());
    }

    @Test
    void restoresExactPomWhenMavenVerificationFails() throws IOException {
        String original = pomWithDependency("1.0.0");
        Files.writeString(project.resolve("pom.xml"), original);
        PatchCandidate candidate = directCandidate("1.0.0", "1.1.0");

        List<AppliedPatch> applied = new MavenPatchWorkflow(
                new MavenPomPatcher(),
                (path, ignored) -> BuildVerificationResult.failure(1, "tests failed"),
                PatchSecurityVerifier.accepting(),
                ignored -> { }
        ).applyRecommendedPatches(project, List.of(candidate));

        assertTrue(applied.isEmpty());
        assertEquals(original, Files.readString(project.resolve("pom.xml")));
    }

    @Test
    void rollsBackWhenSecurityVerifierWasNotConfigured() throws IOException {
        String original = pomWithDependency("1.0.0");
        Files.writeString(project.resolve("pom.xml"), original);

        List<AppliedPatch> applied = new MavenPatchWorkflow(
                new MavenPomPatcher(),
                (path, ignored) -> BuildVerificationResult.success(),
                ignored -> { }
        ).applyRecommendedPatches(project, List.of(directCandidate("1.0.0", "1.1.0")));

        assertTrue(applied.isEmpty());
        assertEquals(original, Files.readString(project.resolve("pom.xml")));
    }

    @Test
    void updatesVersionPropertyOwnedByEffectiveModel() throws IOException {
        Files.writeString(project.resolve("pom.xml"), pomWithProperty("4.1.100.Final"));
        Vulnerability vulnerability = vulnerability("4.1.100.Final", "4.1.110.Final");
        DependencyNode node = node("4.1.100.Final");
        VersionOwner owner = new VersionOwner(
                VersionOwnerType.LOCAL_PROPERTY,
                new ComponentCoordinate("io.netty", "netty-handler", "4.1.100.Final"),
                "netty.version",
                project.resolve("pom.xml")
        );
        MutationPoint point = new MutationPoint(
                MutationType.UPDATE_PROPERTY, owner.coordinate(), node, owner
        );
        FixCandidate fix = new FixCandidate(
                vulnerability,
                node,
                new FixCandidate.ComponentFix(
                        List.of(), new ComponentCoordinate("io.netty", "netty-handler", "4.1.110.Final")
                ),
                false,
                List.of()
        );

        List<AppliedPatch> applied = new MavenPatchWorkflow(
                new MavenPomPatcher(), (path, ignored) -> BuildVerificationResult.success(),
                PatchSecurityVerifier.accepting(), ignored -> { }
        ).applyRecommendedPatches(project, List.of(new PatchCandidate(point, fix)));

        assertEquals(1, applied.size());
        assertTrue(Files.readString(project.resolve("pom.xml")).contains(
                "<netty.version>4.1.110.Final</netty.version>"
        ));
    }

    @Test
    void updatesImportedBomEvenThoughBomIsAbsentFromRuntimeDependencyTree() throws IOException {
        Files.writeString(project.resolve("pom.xml"), pomWithImportedBom("4.1.100.Final"));
        Vulnerability vulnerability = vulnerability("4.1.100.Final", "4.1.110.Final");
        DependencyNode vulnerableNode = node("4.1.100.Final");
        ComponentCoordinate currentBom = new ComponentCoordinate("io.netty", "netty-bom", "4.1.100.Final");
        ComponentCoordinate replacementBom = new ComponentCoordinate("io.netty", "netty-bom", "4.1.110.Final");
        VersionOwner owner = new VersionOwner(
                VersionOwnerType.IMPORTED_BOM, currentBom, null, project.resolve("pom.xml")
        );
        MutationPoint point = new MutationPoint(
                MutationType.UPDATE_IMPORTED_BOM, currentBom, vulnerableNode, owner
        );
        FixCandidate fix = new FixCandidate(
                vulnerability,
                vulnerableNode,
                new FixCandidate.ComponentFix(List.of(), replacementBom),
                false,
                List.of()
        );

        List<AppliedPatch> applied = new MavenPatchWorkflow(
                new MavenPomPatcher(), (path, ignored) -> BuildVerificationResult.success(),
                PatchSecurityVerifier.accepting(), ignored -> { }
        ).applyRecommendedPatches(project, List.of(new PatchCandidate(point, fix)));

        assertEquals(1, applied.size());
        assertTrue(Files.readString(project.resolve("pom.xml")).contains("4.1.110.Final"));
    }

    @Test
    void rollsBackStillVulnerableVersionAndTriesTheNextHigherVersion() throws IOException {
        Files.writeString(project.resolve("pom.xml"), pomWithDependency("1.0.0"));
        PatchCandidate first = directCandidate("1.0.0", "1.1.0");
        PatchCandidate second = directCandidate("1.0.0", "1.2.0");
        PatchSecurityVerifier securityVerifier = (path, candidate) ->
                candidate.candidate().replacement().coordinate().version().equals("1.1.0")
                        ? SecurityVerificationResult.unsafe("CVE-test remains")
                        : SecurityVerificationResult.safeResult();

        List<AppliedPatch> applied = new MavenPatchWorkflow(
                new MavenPomPatcher(),
                (path, candidate) -> BuildVerificationResult.success(),
                securityVerifier,
                ignored -> { }
        ).applyRecommendedPatches(project, List.of(first, second));

        assertEquals(1, applied.size());
        assertEquals("1.2.0", applied.getFirst().candidate().candidate().replacement().coordinate().version());
        String patchedPom = Files.readString(project.resolve("pom.xml"));
        assertTrue(patchedPom.contains("1.2.0"));
        assertTrue(!patchedPom.contains("1.1.0"));
    }

    @Test
    void retriesEarlierBuildFailureAfterLaterPatchChangesDependencyGraph() throws IOException {
        Files.writeString(project.resolve("pom.xml"), pomWithTwoDependencies());
        PatchCandidate first = directCandidate("com.example", "library-a", "1.0.0", "1.1.0", "CVE-a");
        PatchCandidate graphUnlock = directCandidate(
                "com.example", "library-b", "1.0.0", "1.1.0", "CVE-b"
        );
        AtomicBoolean graphWasUnlocked = new AtomicBoolean();
        ProjectBuildVerifier verifier = new ProjectBuildVerifier() {
            @Override
            public BuildVerificationResult verify(Path path, PatchCandidate candidate) {
                boolean firstCandidate = candidate.mutationPoint().component().artifactId().equals("library-a");
                return !firstCandidate || graphWasUnlocked.get()
                        ? BuildVerificationResult.success()
                        : BuildVerificationResult.failure(1, "alignment is not ready");
            }

            @Override
            public void patchCommitted(Path path, PatchCandidate candidate) {
                if (candidate.mutationPoint().component().artifactId().equals("library-b")) {
                    graphWasUnlocked.set(true);
                }
            }
        };

        List<AppliedPatch> applied = new MavenPatchWorkflow(
                new MavenPomPatcher(), verifier, PatchSecurityVerifier.accepting(), ignored -> { }
        ).applyRecommendedPatches(project, List.of(first, graphUnlock));

        assertEquals(2, applied.size());
        String patched = Files.readString(project.resolve("pom.xml"));
        assertTrue(patched.contains("<artifactId>library-a</artifactId>"));
        assertTrue(patched.contains("<artifactId>library-b</artifactId>"));
        assertEquals(2, patched.split("<version>1.1.0</version>", -1).length - 1);
    }

    @Test
    void commitsOnlyFirstSuccessfulAlternativeForOneVulnerability() throws IOException {
        Files.writeString(project.resolve("pom.xml"), pomWithDependency("1.0.0"));
        PatchCandidate first = directCandidate("1.0.0", "1.1.0");
        PatchCandidate second = directCandidate("1.0.0", "1.2.0");

        List<AppliedPatch> applied = new MavenPatchWorkflow(
                new MavenPomPatcher(),
                (path, candidate) -> BuildVerificationResult.success(),
                (path, candidate) -> SecurityVerificationResult.safeResult(),
                ignored -> { }
        ).applyRecommendedPatches(project, List.of(first, second));

        assertEquals(1, applied.size());
        String patchedPom = Files.readString(project.resolve("pom.xml"));
        assertTrue(patchedPom.contains("1.1.0"));
        assertTrue(!patchedPom.contains("1.2.0"));
    }

    @Test
    void bomUpgradeNeverWritesBomVersionIntoVulnerableDependency() throws IOException {
        Files.writeString(project.resolve("pom.xml"), pomWithBomAndExplicitDependency("3.3.0", "4.1.100.Final"));
        Vulnerability vulnerability = vulnerability("4.1.100.Final", "4.1.110.Final");
        DependencyNode vulnerableNode = node("4.1.100.Final");
        ComponentCoordinate currentBom = new ComponentCoordinate("org.example", "platform-bom", "3.3.0");
        VersionOwner owner = new VersionOwner(VersionOwnerType.IMPORTED_BOM, currentBom, null, project.resolve("pom.xml"));
        MutationPoint point = new MutationPoint(MutationType.UPDATE_IMPORTED_BOM, currentBom, vulnerableNode, owner);
        FixCandidate fix = new FixCandidate(
                vulnerability,
                vulnerableNode,
                new FixCandidate.ComponentFix(
                        List.of(), new ComponentCoordinate("org.example", "platform-bom", "3.3.1")
                ),
                false,
                List.of()
        );

        new MavenPatchWorkflow(
                new MavenPomPatcher(),
                (path, candidate) -> BuildVerificationResult.success(),
                PatchSecurityVerifier.accepting(),
                ignored -> { }
        ).applyRecommendedPatches(project, List.of(new PatchCandidate(point, fix)));

        String patchedPom = Files.readString(project.resolve("pom.xml"));
        assertTrue(patchedPom.contains("<artifactId>platform-bom</artifactId>"));
        assertTrue(patchedPom.contains("<version>3.3.1</version>"));
        assertTrue(patchedPom.contains("<artifactId>netty-handler</artifactId>"));
        assertTrue(patchedPom.contains("<version>4.1.100.Final</version>"));
        assertTrue(!patchedPom.contains("<artifactId>netty-handler</artifactId>\n      <version>3.3.1</version>"));
    }

    @Test
    void refusesNonAtomicUpgradeOfLocalRelativePathParent() throws IOException {
        Path child = Files.createDirectories(project.resolve("child"));
        Files.writeString(project.resolve("pom.xml"), """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>parent</artifactId>
                  <version>1.0.0</version>
                  <packaging>pom</packaging>
                </project>
                """);
        String childPom = """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <parent>
                    <groupId>com.example</groupId>
                    <artifactId>parent</artifactId>
                    <version>1.0.0</version>
                  </parent>
                  <artifactId>child</artifactId>
                </project>
                """;
        Files.writeString(child.resolve("pom.xml"), childPom);
        ComponentCoordinate parent = new ComponentCoordinate("com.example", "parent", "1.0.0");
        Vulnerability vulnerability = vulnerability("4.1.100.Final", "4.1.110.Final");
        DependencyNode node = node("4.1.100.Final");
        PatchCandidate candidate = new PatchCandidate(
                new MutationPoint(
                        MutationType.UPDATE_PARENT_POM,
                        parent,
                        node,
                        new VersionOwner(VersionOwnerType.PARENT_POM, parent, null, child.resolve("pom.xml"))
                ),
                new FixCandidate(
                        vulnerability,
                        node,
                        new FixCandidate.ComponentFix(
                                List.of(), new ComponentCoordinate("com.example", "parent", "1.1.0")
                        ),
                        false,
                        List.of()
                )
        );

        assertThrows(PomPatchException.class, () -> new MavenPomPatcher().apply(child, candidate));
        assertEquals(childPom, Files.readString(child.resolve("pom.xml")));
    }

    @Test
    void updatesEverySemanticallyIdenticalDuplicateManagedDeclaration() throws IOException {
        Files.writeString(project.resolve("pom.xml"), pomWithDuplicateManagedDependencies("1.0.0", "1.0.0"));

        PomPatchTransaction transaction = new MavenPomPatcher().apply(
                project,
                managedCandidate("1.0.0", "1.1.0")
        );

        String patched = Files.readString(project.resolve("pom.xml"));
        assertEquals(2, patched.split("<version>1.1.0</version>", -1).length - 1);
        transaction.commit();
    }

    @Test
    void rejectsDuplicateManagedDeclarationsWithDifferentVersionsWithoutChangingPom() throws IOException {
        String original = pomWithDuplicateManagedDependencies("1.0.0", "0.9.0");
        Files.writeString(project.resolve("pom.xml"), original);

        assertThrows(
                PomPatchException.class,
                () -> new MavenPomPatcher().apply(project, managedCandidate("1.0.0", "1.1.0"))
        );
        assertEquals(original, Files.readString(project.resolve("pom.xml")));
    }

    @Test
    void rejectsStaleCandidateInsteadOfOverwritingAlreadyChangedDependency() throws IOException {
        String original = pomWithDependency("1.2.0");
        Files.writeString(project.resolve("pom.xml"), original);

        assertThrows(
                PomPatchException.class,
                () -> new MavenPomPatcher().apply(project, directCandidate("1.0.0", "1.1.0"))
        );
        assertEquals(original, Files.readString(project.resolve("pom.xml")));
    }

    private PatchCandidate directCandidate(String currentVersion, String replacementVersion) {
        Vulnerability vulnerability = vulnerability(currentVersion, replacementVersion);
        DependencyNode node = node(currentVersion);
        ComponentCoordinate current = new ComponentCoordinate("io.netty", "netty-handler", currentVersion);
        MutationPoint point = new MutationPoint(
                MutationType.UPDATE_DIRECT_DEPENDENCY,
                current,
                node,
                new VersionOwner(VersionOwnerType.DIRECT_DEPENDENCY, current, null, project.resolve("pom.xml"))
        );
        FixCandidate fix = new FixCandidate(
                vulnerability,
                node,
                new FixCandidate.ComponentFix(
                        List.of(), new ComponentCoordinate("io.netty", "netty-handler", replacementVersion)
                ),
                true,
                List.of()
        );
        return new PatchCandidate(point, fix);
    }

    private PatchCandidate directCandidate(
            String groupId,
            String artifactId,
            String currentVersion,
            String replacementVersion,
            String vulnerabilityId
    ) {
        Vulnerability vulnerability = new Vulnerability(
                vulnerabilityId, groupId, artifactId, currentVersion, "high", "", ""
        );
        ComponentCoordinate current = new ComponentCoordinate(groupId, artifactId, currentVersion);
        ComponentCoordinate replacement = new ComponentCoordinate(groupId, artifactId, replacementVersion);
        vulnerability.setRemediationCandidate(new RemediationCandidate("upgrade", replacement, true, List.of()));
        DependencyNode dependency = new DependencyNode(artifactId, groupId, currentVersion, "compile", List.of());
        return new PatchCandidate(
                new MutationPoint(
                        MutationType.UPDATE_DIRECT_DEPENDENCY,
                        current,
                        dependency,
                        new VersionOwner(
                                VersionOwnerType.DIRECT_DEPENDENCY, current, null, project.resolve("pom.xml")
                        )
                ),
                new FixCandidate(
                        vulnerability,
                        dependency,
                        new FixCandidate.ComponentFix(List.of(), replacement),
                        true,
                        List.of()
                )
        );
    }

    private PatchCandidate managedCandidate(String currentVersion, String replacementVersion) {
        PatchCandidate direct = directCandidate(currentVersion, replacementVersion);
        ComponentCoordinate current = direct.mutationPoint().component();
        VersionOwner owner = new VersionOwner(
                VersionOwnerType.DEPENDENCY_MANAGEMENT,
                current,
                null,
                project.resolve("pom.xml")
        );
        return new PatchCandidate(
                new MutationPoint(
                        MutationType.UPDATE_DEPENDENCY_MANAGEMENT,
                        current,
                        direct.mutationPoint().resolvedNode(),
                        owner
                ),
                direct.candidate()
        );
    }

    private Vulnerability vulnerability(String currentVersion, String replacementVersion) {
        Vulnerability vulnerability = new Vulnerability(
                "CVE-test", "io.netty", "netty-handler", currentVersion, "high", "", ""
        );
        vulnerability.setRemediationCandidate(new RemediationCandidate(
                "upgrade",
                new ComponentCoordinate("io.netty", "netty-handler", replacementVersion),
                true,
                List.of()
        ));
        return vulnerability;
    }

    private DependencyNode node(String version) {
        return new DependencyNode("netty-handler", "io.netty", version, "compile", List.of());
    }

    private String pomWithDependency(String version) {
        return """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>application</artifactId>
                  <version>1.0.0</version>
                  <dependencies>
                    <dependency>
                      <groupId>io.netty</groupId>
                      <artifactId>netty-handler</artifactId>
                      <version>%s</version>
                    </dependency>
                  </dependencies>
                </project>
                """.formatted(version);
    }

    private String pomWithDuplicateManagedDependencies(String firstVersion, String secondVersion) {
        return """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>application</artifactId>
                  <version>1.0.0</version>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>io.netty</groupId>
                        <artifactId>netty-handler</artifactId>
                        <version>%s</version>
                      </dependency>
                      <dependency>
                        <groupId>io.netty</groupId>
                        <artifactId>netty-handler</artifactId>
                        <version>%s</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """.formatted(firstVersion, secondVersion);
    }

    private String pomWithTwoDependencies() {
        return """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>application</artifactId>
                  <version>1.0.0</version>
                  <dependencies>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>library-a</artifactId>
                      <version>1.0.0</version>
                    </dependency>
                    <dependency>
                      <groupId>com.example</groupId>
                      <artifactId>library-b</artifactId>
                      <version>1.0.0</version>
                    </dependency>
                  </dependencies>
                </project>
                """;
    }

    private String pomWithProperty(String version) {
        return """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>application</artifactId>
                  <version>1.0.0</version>
                  <properties>
                    <netty.version>%s</netty.version>
                  </properties>
                </project>
                """.formatted(version);
    }

    private String pomWithImportedBom(String version) {
        return """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>application</artifactId>
                  <version>1.0.0</version>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>io.netty</groupId>
                        <artifactId>netty-bom</artifactId>
                        <version>%s</version>
                        <type>pom</type>
                        <scope>import</scope>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                </project>
                """.formatted(version);
    }

    private String pomWithBomAndExplicitDependency(String bomVersion, String dependencyVersion) {
        return """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>application</artifactId>
                  <version>1.0.0</version>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>org.example</groupId>
                        <artifactId>platform-bom</artifactId>
                        <version>%s</version>
                        <type>pom</type>
                        <scope>import</scope>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                  <dependencies>
                    <dependency>
                      <groupId>io.netty</groupId>
                      <artifactId>netty-handler</artifactId>
                      <version>%s</version>
                    </dependency>
                  </dependencies>
                </project>
                """.formatted(bomVersion, dependencyVersion);
    }
}

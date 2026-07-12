package com.vulncheck;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/** Tries candidates transactionally and keeps only patches that pass Maven verify. */
public final class MavenPatchWorkflow {

    private final MavenPomPatcher pomPatcher;
    private final ProjectBuildVerifier buildVerifier;
    private final PatchSecurityVerifier securityVerifier;
    private final Consumer<String> console;

    public MavenPatchWorkflow() {
        this(
                new MavenPomPatcher(),
                new MavenProjectBuildVerifier(),
                PatchSecurityVerifier.accepting(),
                System.out::println
        );
    }

    public MavenPatchWorkflow(
            MavenPomPatcher pomPatcher,
            ProjectBuildVerifier buildVerifier,
            Consumer<String> console
    ) {
        this(pomPatcher, buildVerifier, PatchSecurityVerifier.accepting(), console);
    }

    public MavenPatchWorkflow(
            MavenPomPatcher pomPatcher,
            ProjectBuildVerifier buildVerifier,
            PatchSecurityVerifier securityVerifier,
            Consumer<String> console
    ) {
        this.pomPatcher = Objects.requireNonNull(pomPatcher, "pomPatcher must not be null");
        this.buildVerifier = Objects.requireNonNull(buildVerifier, "buildVerifier must not be null");
        this.securityVerifier = Objects.requireNonNull(securityVerifier, "securityVerifier must not be null");
        this.console = Objects.requireNonNull(console, "console must not be null");
    }

    public List<AppliedPatch> applyRecommendedPatches(Path projectPath, List<PatchCandidate> candidates) {
        Map<String, List<PatchCandidate>> byVulnerability = new LinkedHashMap<>();
        candidates.forEach(candidate -> byVulnerability
                .computeIfAbsent(vulnerabilityKey(candidate.candidate().vulnerability()), ignored -> new ArrayList<>())
                .add(candidate));

        List<AppliedPatch> applied = new ArrayList<>();
        byVulnerability.forEach((ignored, alternatives) -> tryAlternatives(projectPath, alternatives, applied));
        return List.copyOf(applied);
    }

    private void tryAlternatives(
            Path projectPath,
            List<PatchCandidate> alternatives,
            List<AppliedPatch> applied
    ) {
        Vulnerability vulnerability = alternatives.getFirst().candidate().vulnerability();
        console.accept("");
        console.accept("[PATCH] " + vulnerability.getId() + " " + vulnerability.component());

        for (PatchCandidate candidate : alternatives) {
            ComponentCoordinate current = candidate.mutationPoint().component();
            ComponentCoordinate replacement = candidate.candidate().replacement().coordinate();
            String source = candidate.recommendationPriority() < 100 ? "SONATYPE" : "REPOSITORY";
            console.accept("  TRY  [" + source + "] " + candidate.mutationPoint().type() + " "
                    + coordinates(current) + " -> " + replacement.version());

            try (PomPatchTransaction transaction = pomPatcher.apply(projectPath, candidate)) {
                console.accept("  RUN  mvn verify + dependency re-resolve");
                BuildVerificationResult verification = buildVerifier.verify(projectPath, candidate);
                if (verification.successful()) {
                    console.accept("  SCAN Sonatype verification");
                    SecurityVerificationResult security = securityVerifier.verify(projectPath, candidate);
                    if (security.safe()) {
                        transaction.commit();
                        applied.add(new AppliedPatch(candidate, verification));
                        console.accept("  OK   patch committed");
                        return;
                    }
                    console.accept("  UNSAFE " + security.failure());
                    console.accept("  UNDO pom.xml restored");
                    continue;
                }
                console.accept("  FAIL Maven exit=" + verification.exitCode()
                        + messageSuffix(verification.failure()));
                console.accept("  UNDO pom.xml restored");
            } catch (RuntimeException exception) {
                console.accept("  SKIP " + exception.getMessage());
            }
        }

        console.accept("  NONE no candidate passed verification");
    }

    private String vulnerabilityKey(Vulnerability vulnerability) {
        return vulnerability.getId() + "|" + vulnerability.getGroupId() + ":"
                + vulnerability.getArtifactId() + ":" + vulnerability.getVersion();
    }

    private String coordinates(ComponentCoordinate coordinate) {
        return coordinate.groupId() + ":" + coordinate.artifactId() + ":" + coordinate.version();
    }

    private String messageSuffix(String message) {
        return message == null || message.isBlank() ? "" : " (" + message + ")";
    }
}

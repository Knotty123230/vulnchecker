package com.vulncheck;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
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
        // Group candidates by mutation point key (type + component + target version)
        // so that multiple CVEs fixed by the same change are tried only once.
        Map<String, List<PatchCandidate>> byMutationAction = new LinkedHashMap<>();
        candidates.forEach(candidate -> byMutationAction
                .computeIfAbsent(mutationActionKey(candidate), ignored -> new ArrayList<>())
                .add(candidate));

        // Cache of already-tried mutation actions: key → success/fail
        Set<String> failedActions = new HashSet<>();
        Set<String> succeededActions = new HashSet<>();
        List<AppliedPatch> applied = new ArrayList<>();

        for (var entry : byMutationAction.entrySet()) {
            String actionKey = entry.getKey();
            List<PatchCandidate> group = entry.getValue();

            // Skip if this exact action already failed
            if (failedActions.contains(actionKey)) {
                group.forEach(c -> console.accept("  CACHE-SKIP " + actionKey + " (previously failed)"));
                continue;
            }

            // If already succeeded (committed), mark all CVEs in this group as fixed
            if (succeededActions.contains(actionKey)) {
                group.forEach(c -> console.accept("  CACHE-HIT " + actionKey + " (already applied)"));
                continue;
            }

            // Try the action once for the whole group
            boolean success = tryMutationAction(projectPath, group, applied);
            if (success) {
                succeededActions.add(actionKey);
            } else {
                failedActions.add(actionKey);
            }
        }

        // Now handle remaining vulnerabilities that weren't in a group
        // Re-group by vulnerability for any that had multiple mutation options
        Map<String, List<PatchCandidate>> byVulnerability = new LinkedHashMap<>();
        candidates.forEach(candidate -> {
            String actionKey = mutationActionKey(candidate);
            // Only process candidates whose action wasn't already resolved
            if (!succeededActions.contains(actionKey) && !failedActions.contains(actionKey)) {
                byVulnerability
                        .computeIfAbsent(vulnerabilityKey(candidate.candidate().vulnerability()), ignored -> new ArrayList<>())
                        .add(candidate);
            }
        });

        byVulnerability.forEach((ignored, alternatives) -> tryAlternatives(projectPath, alternatives, applied, failedActions));

        console.accept("");
        console.accept("Applied " + applied.size() + " verified patch(es).");
        return List.copyOf(applied);
    }

    private boolean tryMutationAction(
            Path projectPath,
            List<PatchCandidate> group,
            List<AppliedPatch> applied
    ) {
        // Use the first candidate as representative — they all share the same mutation
        PatchCandidate representative = group.getFirst();
        Vulnerability vulnerability = representative.candidate().vulnerability();
        ComponentCoordinate current = representative.mutationPoint().component();
        ComponentCoordinate replacement = representative.candidate().replacement().coordinate();
        String source = representative.recommendationPriority() < 100 ? "SONATYPE" : "REPOSITORY";

        // Print affected CVEs
        console.accept("");
        console.accept("[PATCH] " + representative.mutationPoint().type() + " "
                + coordinates(current) + " -> " + replacement.version()
                + " (fixes " + group.size() + " CVE(s))");
        group.forEach(c -> console.accept("        " + c.candidate().vulnerability().getId()
                + " " + c.candidate().vulnerability().component()));

        console.accept("  TRY  [" + source + "] " + representative.mutationPoint().type() + " "
                + coordinates(current) + " -> " + replacement.version());

        try (PomPatchTransaction transaction = pomPatcher.apply(projectPath, representative)) {
            console.accept("  RUN  mvn dependency:tree (resolve only)");
            BuildVerificationResult verification = buildVerifier.verify(projectPath, representative);
            if (verification.successful()) {
                console.accept("  SCAN Sonatype verification");
                SecurityVerificationResult security = securityVerifier.verify(projectPath, representative);
                if (security.safe()) {
                    transaction.commit();
                    applied.add(new AppliedPatch(representative, verification));
                    console.accept("  OK   patch committed — " + group.size() + " CVE(s) fixed");
                    return true;
                }
                console.accept("  UNSAFE " + security.failure());
                console.accept("  UNDO pom.xml restored");
                return false;
            }
            console.accept("  FAIL Maven exit=" + verification.exitCode()
                    + messageSuffix(verification.failure()));
            console.accept("  UNDO pom.xml restored");
            return false;
        } catch (RuntimeException exception) {
            console.accept("  SKIP " + exception.getMessage());
            return false;
        }
    }

    private void tryAlternatives(
            Path projectPath,
            List<PatchCandidate> alternatives,
            List<AppliedPatch> applied,
            Set<String> failedActions
    ) {
        Vulnerability vulnerability = alternatives.getFirst().candidate().vulnerability();
        console.accept("");
        console.accept("[PATCH] " + vulnerability.getId() + " " + vulnerability.component());

        for (PatchCandidate candidate : alternatives) {
            String actionKey = mutationActionKey(candidate);

            // Skip if cached as failed
            if (failedActions.contains(actionKey)) {
                console.accept("  CACHE-SKIP " + candidate.mutationPoint().type() + " "
                        + coordinates(candidate.mutationPoint().component()) + " -> "
                        + candidate.candidate().replacement().coordinate().version() + " (previously failed)");
                continue;
            }

            ComponentCoordinate current = candidate.mutationPoint().component();
            ComponentCoordinate replacement = candidate.candidate().replacement().coordinate();
            String source = candidate.recommendationPriority() < 100 ? "SONATYPE" : "REPOSITORY";
            console.accept("  TRY  [" + source + "] " + candidate.mutationPoint().type() + " "
                    + coordinates(current) + " -> " + replacement.version());

            try (PomPatchTransaction transaction = pomPatcher.apply(projectPath, candidate)) {
                console.accept("  RUN  mvn dependency:tree (resolve only)");
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
                failedActions.add(actionKey);
            } catch (RuntimeException exception) {
                console.accept("  SKIP " + exception.getMessage());
            }
        }

        console.accept("  NONE no candidate passed verification");
    }

    /**
     * Key that uniquely identifies a mutation action (type + what component + to what version).
     * If two CVEs produce the same action, it only needs to be tried once.
     */
    private String mutationActionKey(PatchCandidate candidate) {
        MutationPoint point = candidate.mutationPoint();
        ComponentCoordinate replacement = candidate.candidate().replacement().coordinate();
        return point.type() + "|"
                + point.component().groupId() + ":" + point.component().artifactId() + ":" + point.component().version()
                + "|" + replacement.version();
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

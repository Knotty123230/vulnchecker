package com.vulncheck;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Consumer;

/** Tries alternatives per vulnerability and commits only the first fully verified mutation. */
public final class MavenPatchWorkflow {

    private final MavenPomPatcher pomPatcher;
    private final ProjectBuildVerifier buildVerifier;
    private final PatchSecurityVerifier securityVerifier;
    private final Consumer<String> console;

    public MavenPatchWorkflow() {
        this(new MavenPomPatcher(), new MavenProjectBuildVerifier(), PatchSecurityVerifier.unconfigured(), System.out::println);
    }

    public MavenPatchWorkflow(
            MavenPomPatcher pomPatcher,
            ProjectBuildVerifier buildVerifier,
            Consumer<String> console
    ) {
        this(pomPatcher, buildVerifier, PatchSecurityVerifier.unconfigured(), console);
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
        Map<String, List<PatchCandidate>> alternativesByVulnerability = new LinkedHashMap<>();
        candidates.forEach(candidate -> alternativesByVulnerability
                .computeIfAbsent(vulnerabilityKey(candidate.candidate().vulnerability()), ignored -> new ArrayList<>())
                .add(candidate));

        Map<String, ActionStatus> actionCache = new HashMap<>();
        List<AppliedPatch> applied = new ArrayList<>();
        List<List<PatchCandidate>> pending = new ArrayList<>(alternativesByVulnerability.values());
        int pass = 1;
        while (!pending.isEmpty()) {
            if (pass > 1) {
                console.accept("");
                console.accept("Retrying " + pending.size()
                        + " unresolved patch group(s) after dependency graph changes.");
            }
            int appliedBeforePass = applied.size();
            List<List<PatchCandidate>> unresolved = new ArrayList<>();
            for (List<PatchCandidate> alternatives : pending) {
                if (!tryAlternatives(projectPath, alternatives, applied, actionCache)) {
                    unresolved.add(alternatives);
                }
            }
            if (applied.size() == appliedBeforePass) {
                break;
            }

            // A committed parent/BOM/dependency change can make a previous convergence
            // failure obsolete. Only committed actions remain cacheable across graph states.
            actionCache.entrySet().removeIf(entry -> entry.getValue() == ActionStatus.BUILD_FAILED);
            pending = unresolved;
            pass++;
        }

        console.accept("");
        console.accept("Applied " + applied.size() + " verified patch(es).");
        return List.copyOf(applied);
    }

    private boolean tryAlternatives(
            Path projectPath,
            List<PatchCandidate> alternatives,
            List<AppliedPatch> applied,
            Map<String, ActionStatus> actionCache
    ) {
        Vulnerability vulnerability = alternatives.getFirst().candidate().vulnerability();
        console.accept("");
        console.accept("[PATCH] " + vulnerability.getId() + " " + vulnerability.component());

        for (PatchCandidate candidate : alternatives) {
            String actionKey = mutationActionKey(candidate);
            ActionStatus cached = actionCache.get(actionKey);
            if (cached == ActionStatus.BUILD_FAILED) {
                console.accept("  CACHE-SKIP " + describe(candidate) + " (Maven verification previously failed)");
                continue;
            }
            if (cached == ActionStatus.COMMITTED) {
                SecurityVerificationResult security = securityVerifier.verify(projectPath, candidate);
                if (security.safe()) {
                    console.accept("  CACHE-HIT " + describe(candidate) + " (already applied and CVE verified)");
                    return true;
                }
                console.accept("  CACHE-MISS " + describe(candidate) + messageSuffix(security.failure()));
                continue;
            }

            console.accept("  TRY  " + describe(candidate));
            BuildVerificationResult readiness;
            try {
                readiness = buildVerifier.prepare(projectPath, candidate);
            } catch (RuntimeException exception) {
                actionCache.put(actionKey, ActionStatus.BUILD_FAILED);
                console.accept("  SKIP preflight failed" + messageSuffix(exception.getMessage()));
                continue;
            }
            if (!readiness.successful()) {
                actionCache.put(actionKey, ActionStatus.BUILD_FAILED);
                console.accept("  SKIP preflight failed" + messageSuffix(readiness.failure()));
                continue;
            }
            try (PomPatchTransaction transaction = pomPatcher.apply(projectPath, candidate)) {
                console.accept("  RUN  Maven graph, convergence and test-compile verification");
                BuildVerificationResult verification = buildVerifier.verify(projectPath, candidate);
                if (!verification.successful()) {
                    actionCache.put(actionKey, ActionStatus.BUILD_FAILED);
                    console.accept("  FAIL Maven exit=" + verification.exitCode()
                            + messageSuffix(verification.failure()));
                    console.accept("  UNDO POM restored");
                    continue;
                }

                console.accept("  SCAN Sonatype verification");
                SecurityVerificationResult security = securityVerifier.verify(projectPath, candidate);
                if (!security.safe()) {
                    console.accept("  UNSAFE " + security.failure());
                    console.accept("  UNDO POM restored");
                    continue;
                }

                transaction.commit();
                buildVerifier.patchCommitted(projectPath, candidate);
                actionCache.put(actionKey, ActionStatus.COMMITTED);
                applied.add(new AppliedPatch(candidate, verification));
                String alignment = transaction.mutationCount() > 1
                        ? " (" + transaction.mutationCount() + " aligned version declarations)"
                        : "";
                console.accept("  OK   patch committed" + alignment);
                return true;
            } catch (RuntimeException exception) {
                console.accept("  SKIP " + exception.getMessage());
            }
        }

        console.accept("  NONE no candidate passed verification");
        return false;
    }

    private String describe(PatchCandidate candidate) {
        ComponentCoordinate current = candidate.mutationPoint().component();
        ComponentCoordinate replacement = candidate.candidate().replacement().coordinate();
        String source = candidate.recommendationPriority() < 100 ? "SONATYPE" : "REPOSITORY";
        return "[" + source + "] " + candidate.mutationPoint().type() + " "
                + coordinates(current) + " -> " + replacement.version();
    }

    private String mutationActionKey(PatchCandidate candidate) {
        MutationPoint point = candidate.mutationPoint();
        ComponentCoordinate component = point.component();
        ComponentCoordinate replacement = candidate.candidate().replacement().coordinate();
        VersionOwner owner = point.owner();
        String ownerPath = owner == null || owner.pomPath() == null
                ? "<project-pom>"
                : owner.pomPath().toAbsolutePath().normalize().toString();
        String ownerProperty = owner == null ? null : owner.propertyName();
        String ownerCoordinate = owner == null ? null : coordinates(owner.coordinate());
        return point.type() + "|" + ownerPath + "|" + ownerProperty + "|" + ownerCoordinate
                + "|" + coordinates(component) + "|" + coordinates(replacement);
    }

    private String vulnerabilityKey(Vulnerability vulnerability) {
        return vulnerability.getId() + "|" + vulnerability.getGroupId() + ":"
                + vulnerability.getArtifactId() + ":" + vulnerability.getVersion();
    }

    private String coordinates(ComponentCoordinate coordinate) {
        if (coordinate == null) {
            return "<unknown>";
        }
        return coordinate.groupId() + ":" + coordinate.artifactId() + ":" + coordinate.version();
    }

    private String messageSuffix(String message) {
        return message == null || message.isBlank() ? "" : " (" + message + ")";
    }

    private enum ActionStatus {
        COMMITTED,
        BUILD_FAILED
    }
}

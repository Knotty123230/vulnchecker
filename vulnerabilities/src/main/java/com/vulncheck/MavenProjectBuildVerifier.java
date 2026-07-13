package com.vulncheck;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.maven.shared.invoker.DefaultInvocationRequest;
import org.apache.maven.shared.invoker.DefaultInvoker;
import org.apache.maven.shared.invoker.InvocationOutputHandler;
import org.apache.maven.shared.invoker.InvocationRequest;
import org.apache.maven.shared.invoker.InvocationResult;
import org.apache.maven.shared.invoker.MavenInvocationException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/** Verifies the resolved graph, convergence delta and compilation before a patch is committed. */
public final class MavenProjectBuildVerifier implements ProjectBuildVerifier {

    private static final String DEPENDENCY_TREE_GOAL =
            "org.apache.maven.plugins:maven-dependency-plugin:3.11.0:tree";
    private static final String ENFORCER_GOAL =
            "org.apache.maven.plugins:maven-enforcer-plugin:3.6.3:enforce";
    private static final int MAX_DIAGNOSTIC_LINES = 40;
    private static final int MAX_CAPTURED_LINES = 5_000;

    private final ObjectMapper objectMapper;
    private final ComponentVersionRepository requiredRepository;
    private final ConcurrentMap<Path, BaselineCapture> baselines = new ConcurrentHashMap<>();
    private final ConcurrentMap<Path, Map<String, Set<String>>> verifiedConflicts = new ConcurrentHashMap<>();

    public MavenProjectBuildVerifier() {
        this.objectMapper = new ObjectMapper();
        this.requiredRepository = null;
    }

    public MavenProjectBuildVerifier(NexusRepositoryConfiguration nexus) {
        this.objectMapper = new ObjectMapper();
        this.requiredRepository = nexus == null ? null : new NexusComponentVersionRepository(nexus);
    }

    /** Kept for source compatibility with the previous constructor. */
    public MavenProjectBuildVerifier(MavenEffectiveModelBuilder ignored) {
        this();
    }

    @Override
    public BuildVerificationResult prepare(Path projectPath, PatchCandidate candidate) {
        Path pom = resolvePom(projectPath, candidate);
        BuildVerificationResult baseline = baselines.computeIfAbsent(pom, this::captureBaseline).result();
        if (!baseline.successful()) {
            return baseline;
        }
        String repositoryFailure = verifyRepositoryAvailability(candidate);
        return repositoryFailure == null
                ? BuildVerificationResult.success()
                : BuildVerificationResult.failure(3, repositoryFailure);
    }

    @Override
    public BuildVerificationResult verify(Path projectPath, PatchCandidate candidate) {
        Path pom = resolvePom(projectPath, candidate);
        BaselineCapture baseline = baselines.get(pom);
        if (baseline == null || !baseline.result().successful()) {
            return BuildVerificationResult.failure(-1, "Maven verification baseline was not prepared for " + pom);
        }

        Path outputDirectory = pom.getParent().resolve("target/vulnchecker-verification");
        Path dependencyTree = outputDirectory.resolve("dependency-tree.json");
        DiagnosticOutput diagnostics = new DiagnosticOutput();

        try {
            Files.createDirectories(outputDirectory);
            Files.deleteIfExists(dependencyTree);

            InvocationResult result = execute(invocationRequest(
                    pom,
                    dependencyTree,
                    List.of(DEPENDENCY_TREE_GOAL, "test-compile", ENFORCER_GOAL),
                    diagnostics
            ), diagnostics);

            Map<String, Set<String>> currentConflicts = convergenceConflicts(diagnostics.allContent());
            if (result.getExitCode() != 0) {
                if (diagnostics.truncated()) {
                    return BuildVerificationResult.failure(
                            result.getExitCode(),
                            "Maven output exceeded the safe convergence comparison limit"
                    );
                }
                String regression = convergenceRegression(baseline.conflicts(), currentConflicts);
                if (regression != null) {
                    return BuildVerificationResult.failure(result.getExitCode(), regression);
                }
                if (currentConflicts.isEmpty()) {
                    return BuildVerificationResult.failure(
                            result.getExitCode(), failureMessage(result, diagnostics)
                    );
                }
                // Maven reached Enforcer only after dependency resolution and test compilation.
                // Unchanged pre-existing convergence conflicts are therefore tolerated.
            }

            if (!Files.isRegularFile(dependencyTree)) {
                return BuildVerificationResult.failure(-1, "Maven did not produce the resolved dependency graph");
            }

            MavenDependencyTreeNode root = objectMapper.readValue(dependencyTree.toFile(), MavenDependencyTreeNode.class);
            String graphFailure = verifyExpectedResolution(root, candidate);
            if (graphFailure != null) {
                return BuildVerificationResult.failure(2, graphFailure);
            }
            verifiedConflicts.put(pom, currentConflicts);
            return BuildVerificationResult.success();
        } catch (MavenInvocationException | IOException | VersionRepositoryException exception) {
            return BuildVerificationResult.failure(-1, exception.getMessage());
        }
    }

    @Override
    public void patchCommitted(Path projectPath, PatchCandidate candidate) {
        Path pom = resolvePom(projectPath, candidate);
        Map<String, Set<String>> committed = verifiedConflicts.remove(pom);
        if (committed != null) {
            baselines.put(pom, new BaselineCapture(BuildVerificationResult.success(), committed));
        }
    }

    private BaselineCapture captureBaseline(Path pom) {
        DiagnosticOutput diagnostics = new DiagnosticOutput();
        try {
            InvocationResult result = execute(
                    invocationRequest(pom, null, List.of(ENFORCER_GOAL), diagnostics), diagnostics
            );
            Map<String, Set<String>> conflicts = convergenceConflicts(diagnostics.allContent());
            if (result.getExitCode() != 0 && diagnostics.truncated()) {
                return new BaselineCapture(BuildVerificationResult.failure(
                        result.getExitCode(), "Maven baseline output exceeded the safe comparison limit"
                ), Map.of());
            }
            if (result.getExitCode() == 0 || !conflicts.isEmpty()) {
                return new BaselineCapture(BuildVerificationResult.success(), conflicts);
            }
            return new BaselineCapture(
                    BuildVerificationResult.failure(result.getExitCode(), failureMessage(result, diagnostics)),
                    Map.of()
            );
        } catch (MavenInvocationException exception) {
            return new BaselineCapture(BuildVerificationResult.failure(-1, exception.getMessage()), Map.of());
        }
    }

    private InvocationResult execute(
            InvocationRequest request,
            DiagnosticOutput diagnostics
    ) throws MavenInvocationException {
        DefaultInvoker invoker = new DefaultInvoker();
        invoker.setOutputHandler(diagnostics);
        invoker.setErrorHandler(diagnostics);
        MavenExecutableResolver.configure(invoker);
        return invoker.execute(request);
    }

    private String verifyRepositoryAvailability(PatchCandidate candidate) {
        if (requiredRepository == null) {
            return null;
        }
        ComponentCoordinate replacement = candidate.candidate().replacement().coordinate();
        String extension = switch (candidate.mutationPoint().type()) {
            case UPDATE_IMPORTED_BOM, UPDATE_PARENT_POM -> "pom";
            default -> "jar";
        };
        return requiredRepository.isAvailable(replacement, extension)
                ? null
                : "Replacement cannot be downloaded from the configured Nexus repository: "
                + coordinates(replacement) + "." + extension;
    }

    private InvocationRequest invocationRequest(
            Path pom,
            Path dependencyTree,
            List<String> goals,
            InvocationOutputHandler diagnostics
    ) {
        InvocationRequest request = new DefaultInvocationRequest();
        request.setPomFile(pom.toFile());
        request.setBaseDirectory(pom.getParent().toFile());
        request.setBatchMode(true);
        request.setRecursive(false);
        request.setShowErrors(false);
        request.setQuiet(false);
        request.setOutputHandler(diagnostics);
        request.setErrorHandler(diagnostics);
        request.setThreads("1");
        request.addArgs(goals);

        Properties properties = new Properties();
        properties.setProperty("skipTests", "true");
        properties.setProperty("enforcer.rules", "dependencyConvergence");
        if (dependencyTree != null) {
            properties.setProperty("outputFile", dependencyTree.toAbsolutePath().toString());
            properties.setProperty("outputType", "json");
            properties.setProperty("verbose", "true");
        }
        request.setProperties(properties);
        return request;
    }

    String convergenceRegression(String baselineOutput, String currentOutput) {
        return convergenceRegression(convergenceConflicts(baselineOutput), convergenceConflicts(currentOutput));
    }

    private String convergenceRegression(
            Map<String, Set<String>> baseline,
            Map<String, Set<String>> current
    ) {
        List<String> regressions = new ArrayList<>();
        current.forEach((component, versions) -> {
            Set<String> previousVersions = baseline.get(component);
            if (previousVersions == null) {
                regressions.add(component + " " + versions + " (new conflict)");
            } else if (versions.size() > previousVersions.size()) {
                regressions.add(component + " " + versions + " (was " + previousVersions + ")");
            }
        });
        return regressions.isEmpty()
                ? null
                : "Dependency convergence regression: " + String.join("; ", regressions);
    }

    private Map<String, Set<String>> convergenceConflicts(String output) {
        Map<String, Set<String>> conflicts = new LinkedHashMap<>();
        String currentComponent = null;
        for (String line : output.lines().toList()) {
            String marker = "Dependency convergence error for ";
            int markerIndex = line.indexOf(marker);
            if (markerIndex >= 0) {
                String coordinate = line.substring(markerIndex + marker.length());
                int pathsIndex = coordinate.indexOf(". Paths to dependency are:");
                if (pathsIndex >= 0) {
                    coordinate = coordinate.substring(0, pathsIndex);
                }
                String[] parts = coordinate.split(":");
                if (parts.length >= 4) {
                    currentComponent = parts[0] + ":" + parts[1];
                    conflicts.computeIfAbsent(currentComponent, ignored -> new LinkedHashSet<>())
                            .add(parts[parts.length - 1]);
                }
                continue;
            }

            String dependencyCoordinate = dependencyCoordinate(line);
            if (currentComponent == null || dependencyCoordinate == null) {
                continue;
            }
            String[] parts = dependencyCoordinate.split(":");
            if (parts.length >= 5 && currentComponent.equals(parts[0] + ":" + parts[1])) {
                conflicts.get(currentComponent).add(parts[parts.length - 2]);
            }
        }
        Map<String, Set<String>> immutable = new LinkedHashMap<>();
        conflicts.forEach((component, versions) -> immutable.put(component, Set.copyOf(versions)));
        return Map.copyOf(immutable);
    }

    private String dependencyCoordinate(String line) {
        String trimmed = line.trim();
        int markerLength;
        if (trimmed.startsWith("+-") || trimmed.startsWith("\\-")) {
            markerLength = 2;
        } else {
            return null;
        }
        String coordinate = trimmed.substring(markerLength);
        int whitespace = coordinate.indexOf(' ');
        return whitespace < 0 ? coordinate : coordinate.substring(0, whitespace);
    }

    String verifyExpectedResolution(MavenDependencyTreeNode root, PatchCandidate candidate) {
        Vulnerability vulnerability = candidate.candidate().vulnerability();
        ComponentCoordinate vulnerable = new ComponentCoordinate(
                vulnerability.getGroupId(), vulnerability.getArtifactId(), vulnerability.getVersion()
        );
        if (contains(root, vulnerable)) {
            return "Vulnerable dependency is still resolved: " + coordinates(vulnerable);
        }

        ComponentCoordinate expected = expectedResolvedTarget(candidate);
        if (expected != null && !contains(root, expected)) {
            return "Expected fixed dependency is not resolved: " + coordinates(expected);
        }
        return null;
    }

    private ComponentCoordinate expectedResolvedTarget(PatchCandidate candidate) {
        MutationType type = candidate.mutationPoint().type();
        if (type == MutationType.UPDATE_IMPORTED_BOM
                || type == MutationType.UPDATE_PARENT_DEPENDENCY
                || type == MutationType.UPDATE_PARENT_POM) {
            return null;
        }
        Vulnerability vulnerability = candidate.candidate().vulnerability();
        ComponentCoordinate replacement = candidate.candidate().replacement().coordinate();
        return sameGa(replacement, vulnerability) ? replacement : null;
    }

    private boolean sameGa(ComponentCoordinate coordinate, Vulnerability vulnerability) {
        return coordinate != null
                && coordinate.groupId().equals(vulnerability.getGroupId())
                && coordinate.artifactId().equals(vulnerability.getArtifactId());
    }

    private boolean contains(MavenDependencyTreeNode node, ComponentCoordinate coordinate) {
        if (node == null) {
            return false;
        }
        if (coordinate.groupId().equals(node.groupId())
                && coordinate.artifactId().equals(node.artifactId())
                && coordinate.version().equals(node.version())) {
            return true;
        }
        return node.children() != null && node.children().stream().anyMatch(child -> contains(child, coordinate));
    }

    private String failureMessage(InvocationResult result, DiagnosticOutput diagnostics) {
        String output = diagnostics.allContent();
        String unresolved = output.lines()
                .map(String::trim)
                .filter(line -> line.contains("The following artifacts could not be resolved:"))
                .findFirst()
                .orElse(null);
        if (unresolved != null) {
            return compact(unresolved.replaceFirst("^\\[ERROR]\\s*", ""));
        }
        if (output.contains("REQUESTED ITEM IS QUARANTINED")) {
            return "Nexus Firewall quarantined the requested component";
        }
        Throwable executionFailure = result.getExecutionException();
        if (executionFailure != null && executionFailure.getMessage() != null) {
            return compact(executionFailure.getMessage());
        }
        String relevant = diagnostics.recentLines().stream()
                .map(String::trim)
                .filter(line -> !line.startsWith("at "))
                .filter(line -> !line.startsWith("Caused by:"))
                .filter(line -> !line.equals("[ERROR]") && !line.isBlank())
                .filter(line -> !line.contains("Re-run Maven") && !line.contains("Help 1"))
                .reduce((first, second) -> second)
                .orElse("Maven verification failed");
        return compact(relevant.replaceFirst("^\\[ERROR]\\s*", ""));
    }

    private String compact(String message) {
        return message.length() <= 800 ? message : message.substring(0, 797) + "...";
    }

    private String coordinates(ComponentCoordinate coordinate) {
        return coordinate.groupId() + ":" + coordinate.artifactId() + ":" + coordinate.version();
    }

    private Path resolvePom(Path projectPath, PatchCandidate candidate) {
        Path normalized = projectPath.toAbsolutePath().normalize();
        Path defaultPom = Files.isDirectory(normalized) ? normalized.resolve("pom.xml") : normalized;
        VersionOwner owner = candidate.mutationPoint().owner();
        Path ownerPom = owner == null ? null : owner.pomPath();
        Path pom = ownerPom != null && Files.isRegularFile(ownerPom) ? ownerPom.toAbsolutePath().normalize() : defaultPom;
        if (!Files.isRegularFile(pom)) {
            throw new MavenAnalysisException("pom.xml not found at " + pom);
        }
        return pom;
    }

    private record BaselineCapture(BuildVerificationResult result, Map<String, Set<String>> conflicts) {
    }

    private static final class DiagnosticOutput implements InvocationOutputHandler {
        private final Deque<String> recentLines = new ArrayDeque<>();
        private final List<String> allLines = new ArrayList<>();
        private boolean truncated;

        @Override
        public synchronized void consumeLine(String line) {
            if (line == null || line.isBlank()) {
                return;
            }
            if (allLines.size() < MAX_CAPTURED_LINES) {
                allLines.add(line);
            } else {
                truncated = true;
            }
            recentLines.addLast(line);
            while (recentLines.size() > MAX_DIAGNOSTIC_LINES) {
                recentLines.removeFirst();
            }
        }

        synchronized String allContent() {
            return String.join(System.lineSeparator(), allLines);
        }

        synchronized List<String> recentLines() {
            return List.copyOf(recentLines);
        }

        synchronized boolean truncated() {
            return truncated;
        }
    }
}

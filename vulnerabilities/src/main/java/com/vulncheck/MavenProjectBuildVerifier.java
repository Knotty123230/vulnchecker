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
import java.util.Deque;
import java.util.List;
import java.util.Properties;

/** Verifies the resolved graph, convergence and compilation before a patch is committed. */
public final class MavenProjectBuildVerifier implements ProjectBuildVerifier {

    private static final String DEPENDENCY_TREE_GOAL =
            "org.apache.maven.plugins:maven-dependency-plugin:3.11.0:tree";
    private static final String ENFORCER_GOAL =
            "org.apache.maven.plugins:maven-enforcer-plugin:3.6.3:enforce";
    private static final int MAX_DIAGNOSTIC_LINES = 120;

    private final ObjectMapper objectMapper;
    private final ComponentVersionRepository requiredRepository;

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
    public BuildVerificationResult verify(Path projectPath, PatchCandidate candidate) {
        Path pom = resolvePom(projectPath, candidate);
        Path outputDirectory = pom.getParent().resolve("target/vulnchecker-verification");
        Path dependencyTree = outputDirectory.resolve("dependency-tree.json");
        DiagnosticOutput diagnostics = new DiagnosticOutput();

        try {
            String repositoryFailure = verifyRepositoryAvailability(candidate);
            if (repositoryFailure != null) {
                return BuildVerificationResult.failure(3, repositoryFailure);
            }
            Files.createDirectories(outputDirectory);
            Files.deleteIfExists(dependencyTree);
            InvocationRequest request = invocationRequest(pom, dependencyTree, diagnostics);
            DefaultInvoker invoker = new DefaultInvoker();
            invoker.setOutputHandler(diagnostics);
            invoker.setErrorHandler(diagnostics);
            MavenExecutableResolver.configure(invoker);

            InvocationResult result = invoker.execute(request);
            if (result.getExitCode() != 0) {
                return BuildVerificationResult.failure(result.getExitCode(), failureMessage(result, diagnostics));
            }
            if (!Files.isRegularFile(dependencyTree)) {
                return BuildVerificationResult.failure(-1, "Maven did not produce the resolved dependency graph");
            }

            MavenDependencyTreeNode root = objectMapper.readValue(dependencyTree.toFile(), MavenDependencyTreeNode.class);
            String graphFailure = verifyExpectedResolution(root, candidate);
            return graphFailure == null
                    ? BuildVerificationResult.success()
                    : BuildVerificationResult.failure(2, graphFailure);
        } catch (MavenInvocationException | IOException | VersionRepositoryException exception) {
            return BuildVerificationResult.failure(-1, exception.getMessage());
        }
    }

    private String verifyRepositoryAvailability(PatchCandidate candidate) {
        if (requiredRepository == null) {
            return null;
        }
        ComponentCoordinate replacement = candidate.candidate().replacement().coordinate();
        return requiredRepository.findVersions(replacement).contains(replacement.version())
                ? null
                : "Replacement is absent from the configured Nexus repository: " + coordinates(replacement);
    }

    private InvocationRequest invocationRequest(
            Path pom,
            Path dependencyTree,
            InvocationOutputHandler diagnostics
    ) {
        InvocationRequest request = new DefaultInvocationRequest();
        request.setPomFile(pom.toFile());
        request.setBaseDirectory(pom.getParent().toFile());
        request.setBatchMode(true);
        request.setRecursive(false);
        request.setShowErrors(true);
        request.setQuiet(false);
        request.setOutputHandler(diagnostics);
        request.setErrorHandler(diagnostics);
        request.setThreads("1");
        request.addArgs(List.of(DEPENDENCY_TREE_GOAL, ENFORCER_GOAL, "test-compile"));

        Properties properties = new Properties();
        properties.setProperty("skipTests", "true");
        properties.setProperty("outputFile", dependencyTree.toAbsolutePath().toString());
        properties.setProperty("outputType", "json");
        properties.setProperty("verbose", "true");
        properties.setProperty("enforcer.rules", "dependencyConvergence");
        request.setProperties(properties);
        return request;
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
            // Owner upgrades can legitimately select a newer fixed version than the minimum
            // remediation target, or remove the transitive dependency entirely.
            return null;
        }
        Vulnerability vulnerability = candidate.candidate().vulnerability();
        RemediationCandidate remediation = vulnerability.getRemediationCandidate();
        if (remediation != null && sameGa(remediation.target(), vulnerability)) {
            return remediation.target();
        }
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
        Throwable executionFailure = result.getExecutionException();
        if (executionFailure != null && executionFailure.getMessage() != null) {
            return executionFailure.getMessage();
        }
        String output = diagnostics.content();
        return output.isBlank() ? "Maven verification failed" : output;
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

    private static final class DiagnosticOutput implements InvocationOutputHandler {
        private final Deque<String> lines = new ArrayDeque<>();

        @Override
        public synchronized void consumeLine(String line) {
            if (line == null || line.isBlank()) {
                return;
            }
            lines.addLast(line);
            while (lines.size() > MAX_DIAGNOSTIC_LINES) {
                lines.removeFirst();
            }
        }

        synchronized String content() {
            return String.join(System.lineSeparator(), lines);
        }
    }
}

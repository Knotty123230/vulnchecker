package com.vulncheck;

import org.apache.maven.shared.invoker.DefaultInvocationRequest;
import org.apache.maven.shared.invoker.DefaultInvoker;
import org.apache.maven.shared.invoker.InvocationRequest;
import org.apache.maven.shared.invoker.InvocationResult;
import org.apache.maven.shared.invoker.MavenInvocationException;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Runs the Maven verify lifecycle, including tests and verification plugins. */
public final class MavenProjectBuildVerifier implements ProjectBuildVerifier {

    private final MavenEffectiveModelBuilder effectiveModelBuilder;

    public MavenProjectBuildVerifier() {
        this(new MavenEffectiveModelBuilder());
    }

    public MavenProjectBuildVerifier(MavenEffectiveModelBuilder effectiveModelBuilder) {
        this.effectiveModelBuilder = effectiveModelBuilder;
    }

    @Override
    public BuildVerificationResult verify(Path projectPath, PatchCandidate candidate) {
        Path pom = resolvePom(projectPath);
        InvocationRequest request = new DefaultInvocationRequest();
        request.setPomFile(pom.toFile());
        request.setBaseDirectory(pom.getParent().toFile());
        request.setBatchMode(true);
        request.setShowErrors(true);
        request.setGoals(List.of("verify"));

        try {
            InvocationResult result = new DefaultInvoker().execute(request);
            if (result.getExitCode() != 0) {
                Throwable failure = result.getExecutionException();
                return BuildVerificationResult.failure(
                        result.getExitCode(), failure == null ? "Maven verify failed" : failure.getMessage()
                );
            }

            return vulnerableVersionWasRemoved(projectPath, candidate)
                    ? BuildVerificationResult.success()
                    : BuildVerificationResult.failure(0, "vulnerable version is still present after Maven resolve");
        } catch (MavenInvocationException exception) {
            return BuildVerificationResult.failure(-1, exception.getMessage());
        } catch (MavenAnalysisException exception) {
            return BuildVerificationResult.failure(-1, exception.getMessage());
        }
    }

    private boolean vulnerableVersionWasRemoved(Path projectPath, PatchCandidate candidate) {
        Vulnerability vulnerability = candidate.candidate().vulnerability();
        ComponentCoordinate vulnerable = new ComponentCoordinate(
                vulnerability.getGroupId(), vulnerability.getArtifactId(), vulnerability.getVersion()
        );
        return effectiveModelBuilder.build(projectPath).pathsTo(vulnerable).isEmpty();
    }

    private Path resolvePom(Path projectPath) {
        Path normalized = projectPath.toAbsolutePath().normalize();
        Path pom = Files.isDirectory(normalized) ? normalized.resolve("pom.xml") : normalized;
        if (!Files.isRegularFile(pom)) {
            throw new MavenAnalysisException("pom.xml not found at " + pom);
        }
        return pom;
    }
}

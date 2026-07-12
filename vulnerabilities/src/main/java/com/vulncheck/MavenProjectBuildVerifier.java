package com.vulncheck;

import org.apache.maven.shared.invoker.DefaultInvocationRequest;
import org.apache.maven.shared.invoker.DefaultInvoker;
import org.apache.maven.shared.invoker.InvocationOutputHandler;
import org.apache.maven.shared.invoker.InvocationRequest;
import org.apache.maven.shared.invoker.InvocationResult;
import org.apache.maven.shared.invoker.MavenInvocationException;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

/** Verifies a patch by resolving the dependency tree (without running tests). */
public final class MavenProjectBuildVerifier implements ProjectBuildVerifier {

    private static final InvocationOutputHandler SILENT = line -> {};

    public MavenProjectBuildVerifier() {
    }

    public MavenProjectBuildVerifier(MavenEffectiveModelBuilder effectiveModelBuilder) {
        // kept for backward compatibility
    }

    @Override
    public BuildVerificationResult verify(Path projectPath, PatchCandidate candidate) {
        Path pom = resolvePom(projectPath);
        InvocationRequest request = new DefaultInvocationRequest();
        request.setPomFile(pom.toFile());
        request.setBaseDirectory(pom.getParent().toFile());
        request.setBatchMode(true);
        request.setShowErrors(false);
        request.setQuiet(true);
        request.setOutputHandler(SILENT);
        request.setErrorHandler(SILENT);
        request.setThreads("1C");
        request.setGoals(List.of(
                "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree"
        ));
        java.util.Properties properties = new java.util.Properties();
        properties.setProperty("skipTests", "true");
        request.setProperties(properties);

        try {
            DefaultInvoker invoker = new DefaultInvoker();
            invoker.setOutputHandler(SILENT);
            invoker.setErrorHandler(SILENT);
            String mavenHome = MavenHomeResolver.resolve();
            if (mavenHome != null) {
                invoker.setMavenHome(new java.io.File(mavenHome));
            }
            InvocationResult result = invoker.execute(request);
            if (result.getExitCode() != 0) {
                Throwable failure = result.getExecutionException();
                return BuildVerificationResult.failure(
                        result.getExitCode(), failure == null ? "Maven resolve failed" : failure.getMessage()
                );
            }

            return BuildVerificationResult.success();
        } catch (MavenInvocationException exception) {
            return BuildVerificationResult.failure(-1, exception.getMessage());
        }
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

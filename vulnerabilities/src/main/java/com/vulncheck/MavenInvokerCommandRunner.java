package com.vulncheck;

import org.apache.maven.shared.invoker.DefaultInvocationRequest;
import org.apache.maven.shared.invoker.DefaultInvoker;
import org.apache.maven.shared.invoker.InvocationRequest;
import org.apache.maven.shared.invoker.InvocationResult;
import org.apache.maven.shared.invoker.MavenInvocationException;

import java.nio.file.Path;
import java.util.List;
import java.util.Properties;

/** Executes Maven through the Maven Shared Invoker API rather than shell parsing. */
public final class MavenInvokerCommandRunner implements MavenCommandRunner {

    private static final String EFFECTIVE_POM_GOAL =
            "org.apache.maven.plugins:maven-help-plugin:3.5.2:effective-pom";
    private static final String DEPENDENCY_TREE_GOAL =
            "org.apache.maven.plugins:maven-dependency-plugin:3.8.1:tree";

    @Override
    public void generateModelAndDependencyTree(
            Path pom,
            Path effectivePomOutput,
            Path dependencyTreeOutput
    ) {
        Properties properties = new Properties();
        properties.setProperty("verbose", "true");
        properties.setProperty("output", effectivePomOutput.toAbsolutePath().toString());
        properties.setProperty("outputFile", dependencyTreeOutput.toAbsolutePath().toString());
        properties.setProperty("outputType", "json");

        InvocationRequest request = new DefaultInvocationRequest();
        request.setPomFile(pom.toFile());
        request.setBaseDirectory(pom.getParent().toFile());
        request.setBatchMode(true);
        request.setRecursive(false);
        request.setShowErrors(true);
        request.setGoals(List.of(EFFECTIVE_POM_GOAL, DEPENDENCY_TREE_GOAL));
        request.setProperties(properties);

        try {
            InvocationResult result = new DefaultInvoker().execute(request);
            if (result.getExitCode() != 0) {
                throw new MavenAnalysisException(
                        "Maven analysis failed with exit code " + result.getExitCode(),
                        result.getExecutionException()
                );
            }
        } catch (MavenInvocationException exception) {
            throw new MavenAnalysisException("Unable to execute Maven for " + pom, exception);
        }
    }
}

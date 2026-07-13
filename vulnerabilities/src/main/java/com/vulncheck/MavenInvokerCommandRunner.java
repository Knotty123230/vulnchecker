package com.vulncheck;

import org.apache.maven.shared.invoker.DefaultInvocationRequest;
import org.apache.maven.shared.invoker.DefaultInvoker;
import org.apache.maven.shared.invoker.InvocationOutputHandler;
import org.apache.maven.shared.invoker.InvocationRequest;
import org.apache.maven.shared.invoker.InvocationResult;
import org.apache.maven.shared.invoker.MavenInvocationException;

import java.nio.file.Path;
import java.util.List;
import java.util.Properties;

/** Executes Maven through the Maven Shared Invoker API rather than shell parsing. */
public final class MavenInvokerCommandRunner implements MavenCommandRunner {

    private static final InvocationOutputHandler SILENT = line -> {};
    private static final String EFFECTIVE_POM_GOAL =
            "org.apache.maven.plugins:maven-help-plugin:3.5.2:effective-pom";
    private static final String DEPENDENCY_TREE_GOAL =
            "org.apache.maven.plugins:maven-dependency-plugin:3.11.0:tree";

    @Override
    public void generateModelAndDependencyTree(
            Path pom,
            Path effectivePomOutput,
            Path dependencyTreeOutput
    ) {
        Properties effectivePomProperties = new Properties();
        effectivePomProperties.setProperty("verbose", "true");
        effectivePomProperties.setProperty("output", effectivePomOutput.toAbsolutePath().toString());
        execute(pom, EFFECTIVE_POM_GOAL, effectivePomProperties, "effective POM generation");

        Properties dependencyTreeProperties = new Properties();
        dependencyTreeProperties.setProperty("outputFile", dependencyTreeOutput.toAbsolutePath().toString());
        dependencyTreeProperties.setProperty("outputType", "json");
        execute(pom, DEPENDENCY_TREE_GOAL, dependencyTreeProperties, "resolved dependency tree generation");
    }

    private void execute(Path pom, String goal, Properties properties, String operation) {
        InvocationRequest request = new DefaultInvocationRequest();
        request.setPomFile(pom.toFile());
        request.setBaseDirectory(pom.getParent().toFile());
        request.setBatchMode(true);
        request.setRecursive(false);
        request.setShowErrors(false);
        request.setQuiet(true);
        request.setOutputHandler(SILENT);
        request.setErrorHandler(SILENT);
        request.setThreads("1C");
        request.addArgs(List.of(goal));
        request.setProperties(properties);

        try {
            DefaultInvoker invoker = new DefaultInvoker();
            invoker.setOutputHandler(SILENT);
            invoker.setErrorHandler(SILENT);
            MavenExecutableResolver.configure(invoker);

            InvocationResult result = invoker.execute(request);
            if (result.getExitCode() != 0) {
                throw new MavenAnalysisException(
                        "Maven " + operation + " failed with exit code " + result.getExitCode(),
                        result.getExecutionException()
                );
            }
        } catch (MavenInvocationException exception) {
            throw new MavenAnalysisException("Unable to execute Maven " + operation + " for " + pom, exception);
        }
    }
}

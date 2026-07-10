package com.vulncheck;

import picocli.CommandLine;

import java.nio.file.Path;
import java.util.List;

@CommandLine.Command(
        name = "vulnfix",
        description = "A tool to scan and fix vulnerabilities in your project.",
        mixinStandardHelpOptions = true,
        version = "vulnfix 1.0",
        subcommands = {VulnScanner.InitCommand.class, VulnScanner.ScanCommand.class}
)
public class VulnScanner implements Runnable {

    @Override
    public void run() {
        System.out.println("Welcome to VulnFix! Run 'vulnfix init' once, then use 'vulnfix scan'.");
    }


    public static void main(String[] args) {
        int exitCode = new CommandLine(new VulnScanner()).execute(args);
        System.exit(exitCode);
    }

    @CommandLine.Command(
            name = "init",
            description = "Create the local Sonatype configuration.",
            mixinStandardHelpOptions = true
    )
    static class InitCommand implements Runnable {

        @CommandLine.Option(names = {"-su", "--sonatype-username"}, required = true,
                description = "Sonatype username.")
        private String username;

        @CommandLine.Option(names = {"-sp", "--sonatype-password"}, required = true, interactive = true,
                description = "Sonatype password.")
        private String password;

        @CommandLine.Option(names = {"-sa", "--sonatype-api-key"},
                description = "Optional Sonatype API key.")
        private String apiKey;

        @CommandLine.Option(names = {"-sb", "--sonatype-base-url"}, required = true,
                description = "Nexus Lifecycle IQ base URL, for example https://iq.example.com.")
        private String baseUrl;

        @CommandLine.Option(names = "--request-timeout", defaultValue = "PT30S",
                description = "HTTP request timeout in ISO-8601 duration format.")
        private String requestTimeout;

        @CommandLine.Option(names = "--scan-timeout", defaultValue = "PT30S",
                description = "Total scan wait timeout in ISO-8601 duration format.")
        private String scanTimeout;

        @CommandLine.Option(names = {"-f", "--force"},
                description = "Overwrite an existing configuration.")
        private boolean force;

        @Override
        public void run() {
            VulnScannerConfiguration configuration = new VulnScannerConfiguration(
                    new SonatypeCredentials(username, password, apiKey, baseUrl, requestTimeout, scanTimeout)
            );
            Path configPath = new VulnScannerConfigStore().save(configuration, force);
            System.out.println("Configuration saved to " + configPath);
        }
    }


    @CommandLine.Command(
            name = "scan",
            description = "Scan the project for vulnerabilities.",
            mixinStandardHelpOptions = true
    )
    static class ScanCommand implements Runnable {

        @CommandLine.Option(
                names = {"-p", "--path"},
                description = "Path to the project to scan for vulnerabilities.",
                required = true
        )
        private Path path;
        @CommandLine.Option(
                names = {"-s", "--svg"},
                description = "Path to the output SVG file."
        )
        private Path svgPath;
        @CommandLine.Option(
                names = {"-id", "--project-id"},
                required = true,
                description = "Sonatype application ID to scan."
        )
        private String projectId;
        private final DependencyNodeFinder dependencyNodeFinder = new MavenDependencyNodeFinder();
        private final GraphGenerator graphGenerator = new GraphGenerator();

        @Override
        public void run() {
            VulnScannerConfiguration configuration = new VulnScannerConfigStore().load();
            DependencyNode dependencyNode = dependencyNodeFinder.find(path);
            DependencyGraph graph = graphGenerator.generateGraph(dependencyNode);
            VulnerabilitiesScanner sonatypeVulnerabilitiesScanner = new SonatypeVulnerabilitiesScanner(configuration.credentials());
            List<Vulnerability> vulnerabilities = sonatypeVulnerabilitiesScanner.scanDependencies(projectId, dependencyNode);
            vulnerabilities.forEach(System.out::println);
            if (svgPath != null) {
                Path outputPath = graph.exportSvg(svgPath.normalize());
                System.out.println("Dependency graph exported to %s".formatted(outputPath));
            }
        }
    }
}

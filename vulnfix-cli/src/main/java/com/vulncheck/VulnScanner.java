package com.vulncheck;

import picocli.CommandLine;

import java.nio.file.Path;
import java.util.List;

@CommandLine.Command(
        name = "vulnfix",
        description = "A tool to scan and fix vulnerabilities in your project.",
        mixinStandardHelpOptions = true,
        version = "vulnfix 1.0",
        subcommands = {VulnScanner.ScanCommand.class}
)
public class VulnScanner implements Runnable {

    @Override
    public void run() {
        IO.println("Welcome to VulnFix! Use the 'scan' command to scan your project for vulnerabilities.");
    }


    static void main(String[] args) {
        int exitCode = new CommandLine(new VulnScanner()).execute(args);
        System.exit(exitCode);
    }


    @CommandLine.Command(
            name = "scan",
            description = "Scan the project for vulnerabilities."
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
                names = {"-su", "--sonatype-username"}
        )
        private String sonatypeUsername;
        @CommandLine.Option(
                names = {"-sp", "--sonatype-password"}
        )
        private String sonatypePassword;
        @CommandLine.Option(
                names = {"-sa", "--sonatype-api-key"}
        )
        private String sonatypeApiKey;
        @CommandLine.Option(
                names = {"-sb", "--sonatype-base-url"}
        )
        private String sonatypeUrl;
        @CommandLine.Option(
                names = {"-id", "--project-id"},
                description = "Sonatype project ID."
        )
        private int projectId;
        private final DependencyNodeFinder dependencyNodeFinder = new MavenDependencyNodeFinder();
        private final GraphGenerator graphGenerator = new GraphGenerator();
        private final VulnerabilitiesScanner sonatypeVulnerabilitiesScanner = new SonatypeVulnerabilitiesScanner(sonatypeApiKey, sonatypeUsername, sonatypePassword, sonatypeUrl);

        @Override
        public void run() {
            DependencyNode dependencyNode = dependencyNodeFinder.find(path);
            DependencyGraph graph = graphGenerator.generateGraph(dependencyNode);
            List<Vulnerability> vulnerabiliesInfo = sonatypeVulnerabilitiesScanner.scanDependencies(projectId, dependencyNode);
            if (svgPath != null) {
                Path outputPath = graph.exportSvg(svgPath.normalize());
                IO.println("Dependency graph exported to %s".formatted(outputPath));
            }

        }
    }
}

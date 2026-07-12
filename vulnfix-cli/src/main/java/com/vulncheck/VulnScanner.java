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

        @CommandLine.Option(names = "--nexus-base-url",
                description = "Optional Nexus Repository base URL, for example https://nexus.example.com.")
        private String nexusBaseUrl;

        @CommandLine.Option(names = "--nexus-repository",
                description = "Nexus Maven repository name used for version discovery.")
        private String nexusRepository;

        @CommandLine.Option(names = "--nexus-username", description = "Optional Nexus username.")
        private String nexusUsername;

        @CommandLine.Option(names = "--nexus-password", interactive = true,
                description = "Optional Nexus password.")
        private String nexusPassword;

        @CommandLine.Option(names = "--nexus-token", interactive = true,
                description = "Optional Nexus bearer token.")
        private String nexusToken;

        @CommandLine.Option(names = "--nexus-timeout", defaultValue = "PT30S",
                description = "Nexus request timeout in ISO-8601 duration format.")
        private String nexusTimeout;

        @CommandLine.Option(names = {"-f", "--force"},
                description = "Overwrite an existing configuration.")
        private boolean force;

        @Override
        public void run() {
            VulnScannerConfiguration configuration = new VulnScannerConfiguration(
                    new SonatypeCredentials(username, password, apiKey, baseUrl, requestTimeout, scanTimeout),
                    nexusConfiguration()
            );
            Path configPath = new VulnScannerConfigStore().save(configuration, force);
            System.out.println("Configuration saved to " + configPath);
        }

        private NexusRepositoryConfiguration nexusConfiguration() {
            if (nexusBaseUrl == null || nexusBaseUrl.isBlank()) {
                return null;
            }
            return new NexusRepositoryConfiguration(
                    nexusBaseUrl,
                    nexusRepository,
                    nexusUsername,
                    nexusPassword,
                    nexusToken,
                    java.time.Duration.parse(nexusTimeout)
            );
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
            //TODO: here maven project, but can be gradle or other, then add other package managers
            VulnerabilitiesScanner sonatypeVulnerabilitiesScanner = new SonatypeVulnerabilitiesScanner(configuration.credentials());
            List<Vulnerability> vulnerabilities = sonatypeVulnerabilitiesScanner.scanDependencies(projectId, dependencyNode);

            printReport(vulnerabilities);
            ComponentVersionRepository versionRepository = configuration.nexusRepository() == null
                    ? ComponentVersionRepository.empty()
                    : new ResilientComponentVersionRepository(
                            new NexusComponentVersionRepository(configuration.nexusRepository()),
                            System.out::println
                    );
            if (configuration.nexusRepository() == null) {
                System.out.println("Nexus is not configured; repository version fallback is disabled.");
            }
            List<PatchCandidate> candidates = new VulnerabilitiesFixer(vulnerabilities, graph, path, versionRepository)
                    .findPatchCandidates();

            System.out.println();
            System.out.println("Found %d actionable patch candidate(s).".formatted(candidates.size()));
            MavenPatchWorkflow patchWorkflow = new MavenPatchWorkflow(
                    new MavenPomPatcher(),
                    new MavenProjectBuildVerifier(),
                    new SonatypePatchSecurityVerifier(
                            projectId, dependencyNodeFinder, sonatypeVulnerabilitiesScanner
                    ),
                    System.out::println
            );
            List<AppliedPatch> applied = patchWorkflow.applyRecommendedPatches(path, candidates);
            System.out.println();
            System.out.println("Applied %d verified patch(es).".formatted(applied.size()));

            if (!applied.isEmpty()) {
                System.out.println("Rebuilding dependency graph and rescanning with Sonatype...");
                dependencyNode = dependencyNodeFinder.find(path);
                graph = graphGenerator.generateGraph(dependencyNode);
                vulnerabilities = sonatypeVulnerabilitiesScanner.scanDependencies(projectId, dependencyNode);
                System.out.println();
                System.out.println("Post-patch vulnerability report:");
                printReport(vulnerabilities);
            }

            if (svgPath != null) {
                Path outputPath = graph.exportSvg(svgPath.normalize());
                System.out.println("Dependency graph exported to %s".formatted(outputPath));
            }
        }

        private void printReport(List<Vulnerability> vulnerabilities) {
            String RED = "\033[0;31m";
            String YELLOW = "\033[1;33m";
            String GREEN = "\033[0;32m";
            String CYAN = "\033[0;36m";
            String BOLD = "\033[1m";
            String DIM = "\033[2m";
            String RESET = "\033[0m";

            System.out.println();
            System.out.println(BOLD + "Found " + vulnerabilities.size() + " vulnerabilities" + RESET);
            System.out.println(DIM + "─".repeat(70) + RESET);

            // Group by component
            java.util.Map<String, List<Vulnerability>> grouped = new java.util.LinkedHashMap<>();
            for (Vulnerability v : vulnerabilities) {
                String key = v.getGroupId() + ":" + v.getArtifactId() + ":" + v.getVersion();
                grouped.computeIfAbsent(key, k -> new java.util.ArrayList<>()).add(v);
            }

            int fixable = 0;
            int unfixable = 0;

            for (var entry : grouped.entrySet()) {
                List<Vulnerability> vulns = entry.getValue();
                Vulnerability first = vulns.getFirst();
                RemediationCandidate remediation = vulns.stream()
                        .map(Vulnerability::getRemediationCandidate)
                        .filter(java.util.Objects::nonNull)
                        .findFirst()
                        .orElse(null);

                // Severity color for the worst CVE in this component
                String sevColor = vulns.stream()
                        .anyMatch(v -> "critical".equals(v.getSeverity())) ? RED
                        : vulns.stream().anyMatch(v -> "severe".equals(v.getSeverity())) ? RED
                          : YELLOW;

                // Component line
                String component = first.getGroupId() + ":" + first.getArtifactId();
                System.out.printf("%n  %s●%s %s%s%s : %s%s", sevColor, RESET, BOLD, component, RESET, first.getVersion(), RESET);

                if (remediation != null && remediation.target() != null) {
                    System.out.printf("  →  %s%s%s", GREEN, remediation.target().version(), RESET);
                    fixable++;

                    // Parent info (transitive dependency)
                    if (!remediation.directDependency() && remediation.parentCandidates() != null && !remediation.parentCandidates().isEmpty()) {
                        ComponentCoordinate parent = remediation.parentCandidates().getFirst();
                        System.out.printf("  %s(via %s:%s → %s)%s",
                                DIM, parent.groupId(), parent.artifactId(), parent.version(), RESET);
                    }

                    System.out.printf("  %s[%s]%s", DIM, remediation.type(), RESET);
                } else {
                    System.out.printf("  %s(no fix available)%s", DIM, RESET);
                    unfixable++;
                }
                System.out.println();

                // CVE list
                for (Vulnerability v : vulns) {
                    String severity = v.getSeverity() != null ? v.getSeverity().toUpperCase() : "?";
                    String sColor = switch (severity) {
                        case "CRITICAL" -> RED;
                        case "SEVERE" -> RED;
                        case "MODERATE" -> YELLOW;
                        default -> DIM;
                    };
                    System.out.printf("    %s%-8s%s %s%s%s%n", sColor, severity, RESET, DIM, v.getId(), RESET);
                }
            }

            // Summary
            System.out.println();
            System.out.println(DIM + "─".repeat(70) + RESET);
            System.out.printf("%s%d%s components affected, %s%s%d fixable%s, %s%d without fix%s%n",
                    BOLD, grouped.size(), RESET,
                    GREEN, BOLD, fixable, RESET,
                    DIM, unfixable, RESET);
            System.out.println();
        }
    }
}

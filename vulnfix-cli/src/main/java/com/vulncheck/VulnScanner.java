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
                    System.out::println
            );
            List<AppliedPatch> applied = patchWorkflow.applyRecommendedPatches(path, candidates);
            System.out.println();
            System.out.println("Applied %d verified patch(es).".formatted(applied.size()));

            // Re-scan loop: keep fixing until all resolved or nothing more can be fixed
            int iteration = 1;
            int totalApplied = applied.size();
            while (!applied.isEmpty()) {
                iteration++;
                System.out.println();
                System.out.println("═══ Re-scan iteration %d ═══".formatted(iteration));
                System.out.println("Rebuilding dependency tree and rescanning...");

                dependencyNode = dependencyNodeFinder.find(path);
                graph = graphGenerator.generateGraph(dependencyNode);
                vulnerabilities = sonatypeVulnerabilitiesScanner.scanDependencies(projectId, dependencyNode);

                // Check if anything fixable remains
                long fixable = vulnerabilities.stream()
                        .filter(v -> v.getRemediationCandidate() != null && v.getRemediationCandidate().target() != null)
                        .count();

                if (fixable == 0) {
                    System.out.println("No more fixable vulnerabilities. Done.");
                    break;
                }

                System.out.println("%d fixable vulnerabilities remaining. Attempting fixes...".formatted(fixable));

                candidates = new VulnerabilitiesFixer(vulnerabilities, graph, path, versionRepository)
                        .findPatchCandidates();

                if (candidates.isEmpty()) {
                    System.out.println("No more patch candidates via parent upgrade. Trying direct overrides...");
                    int overrides = applyDirectOverrides(path, vulnerabilities);
                    totalApplied += overrides;
                    break;
                }

                applied = patchWorkflow.applyRecommendedPatches(path, candidates);
                totalApplied += applied.size();

                if (applied.isEmpty()) {
                    System.out.println("No patches could be applied via parent upgrade. Trying direct overrides...");
                    int overrides = applyDirectOverrides(path, vulnerabilities);
                    totalApplied += overrides;
                    break;
                }

                System.out.println("Applied %d more patch(es) (total: %d).".formatted(applied.size(), totalApplied));
            }

            // Final report
            System.out.println();
            System.out.println("═══ Final vulnerability report ═══");
            dependencyNode = dependencyNodeFinder.find(path);
            graph = graphGenerator.generateGraph(dependencyNode);
            vulnerabilities = sonatypeVulnerabilitiesScanner.scanDependencies(projectId, dependencyNode);
            printReport(vulnerabilities);
            System.out.println("Total patches applied: %d".formatted(totalApplied));

            // Report: blocked breaking changes (Sonatype recommends but requires major/minor bump)
            printBlockedRecommendations(vulnerabilities);

            // Report: available BOM/parent upgrades not applied
            printAvailableBomUpgrades(path);

            if (svgPath != null) {
                Path outputPath = graph.exportSvg(svgPath.normalize());
                System.out.println("Dependency graph exported to %s".formatted(outputPath));
            }
        }

        /**
         * Reports vulnerabilities where Sonatype has a fix but it requires a breaking version change.
         */
        private void printBlockedRecommendations(List<Vulnerability> vulnerabilities) {
            String YELLOW = "\033[1;33m";
            String BOLD = "\033[1m";
            String DIM = "\033[2m";
            String RESET = "\033[0m";

            List<Vulnerability> blocked = vulnerabilities.stream()
                    .filter(v -> v.getRemediationCandidate() != null && v.getRemediationCandidate().target() != null)
                    .filter(v -> !isCompatibleVersion(v.getVersion(), v.getRemediationCandidate().target().version()))
                    .toList();

            if (blocked.isEmpty()) return;

            System.out.println();
            System.out.println(BOLD + "⚠ Blocked breaking changes (manual review required):" + RESET);
            System.out.println(DIM + "─".repeat(70) + RESET);

            // Group by component
            java.util.Map<String, List<Vulnerability>> grouped = new java.util.LinkedHashMap<>();
            for (Vulnerability v : blocked) {
                String key = v.getGroupId() + ":" + v.getArtifactId();
                grouped.computeIfAbsent(key, k -> new java.util.ArrayList<>()).add(v);
            }

            for (var entry : grouped.entrySet()) {
                Vulnerability first = entry.getValue().getFirst();
                String fixVersion = first.getRemediationCandidate().target().version();
                System.out.printf("  %s⚠%s %s : %s → %s%s%s (breaking minor/major change)%n",
                        YELLOW, RESET, entry.getKey(), first.getVersion(), YELLOW, fixVersion, RESET);
                for (Vulnerability v : entry.getValue()) {
                    System.out.printf("    %s%s%s%n", DIM, v.getId(), RESET);
                }
            }
        }

        /**
         * Shows the latest available BOM versions that were not applied due to constraints.
         */
        private void printAvailableBomUpgrades(Path projectPath) {
            String CYAN = "\033[0;36m";
            String BOLD = "\033[1m";
            String DIM = "\033[2m";
            String RESET = "\033[0m";

            Path pom = projectPath.toAbsolutePath().normalize();
            if (java.nio.file.Files.isDirectory(pom)) pom = pom.resolve("pom.xml");

            try {
                String content = java.nio.file.Files.readString(pom, java.nio.charset.StandardCharsets.UTF_8);

                // Extract current parent version
                java.util.regex.Matcher parentMatcher = java.util.regex.Pattern.compile(
                        "<parent>.*?<groupId>([^<]+)</groupId>.*?<artifactId>([^<]+)</artifactId>.*?<version>([^<]+)</version>",
                        java.util.regex.Pattern.DOTALL
                ).matcher(content);

                System.out.println();
                System.out.println(BOLD + "📋 Current BOM/Parent versions:" + RESET);
                System.out.println(DIM + "─".repeat(70) + RESET);

                if (parentMatcher.find()) {
                    String g = parentMatcher.group(1).trim();
                    String a = parentMatcher.group(2).trim();
                    String v = parentMatcher.group(3).trim();
                    System.out.printf("  parent: %s%s:%s:%s%s%n", CYAN, g, a, v, RESET);

                    // Show what next major version exists
                    String major = v.contains(".") ? v.substring(0, v.indexOf('.')) : v;
                    int nextMajor = Integer.parseInt(major) + 1;
                    System.out.printf("    %s→ next major: %d.x (requires manual migration)%s%n", DIM, nextMajor, RESET);
                }

                // Extract imported BOMs
                java.util.regex.Pattern bomPattern = java.util.regex.Pattern.compile(
                        "<dependency>\\s*<groupId>([^<]+)</groupId>\\s*<artifactId>([^<]+)</artifactId>\\s*<version>([^<]+)</version>\\s*<scope>import</scope>",
                        java.util.regex.Pattern.DOTALL
                );
                java.util.regex.Matcher bomMatcher = bomPattern.matcher(content);
                while (bomMatcher.find()) {
                    String g = bomMatcher.group(1).trim();
                    String a = bomMatcher.group(2).trim();
                    String v = bomMatcher.group(3).trim();
                    System.out.printf("  BOM:    %s%s:%s:%s%s%n", CYAN, g, a, v, RESET);
                }

                System.out.println();
                System.out.println(DIM + "To resolve remaining vulnerabilities, consider:" + RESET);
                System.out.println(DIM + "  • Manual migration to next major Spring Boot version" + RESET);
                System.out.println(DIM + "  • Adding exclusions for unused vulnerable transitive dependencies" + RESET);
                System.out.println(DIM + "  • Requesting waivers in Sonatype for accepted risks" + RESET);

            } catch (java.io.IOException e) {
                // ignore
            }
        }

        private boolean isCompatibleVersion(String current, String target) {
            if (current == null || target == null) return true;
            String currentPrefix = compatPrefix(current);
            String targetPrefix = compatPrefix(target);
            return currentPrefix.equals(targetPrefix);
        }

        private String compatPrefix(String version) {
            String[] segments = version.split("[.-]");
            int numericSegments = 0;
            for (String seg : segments) {
                if (seg.matches("\\d+")) numericSegments++;
                else break;
            }
            if (numericSegments >= 4 || (numericSegments == 3 && segments.length > 3)) {
                int firstDot = version.indexOf('.');
                if (firstDot < 0) return version;
                int secondDot = version.indexOf('.', firstDot + 1);
                return secondDot > 0 ? version.substring(0, secondDot) : version;
            }
            int dot = version.indexOf('.');
            return dot > 0 ? version.substring(0, dot) : version;
        }

        /**
         * Fallback: directly insert version overrides in dependencyManagement
         * for vulnerabilities that have a fix but couldn't be resolved by upgrading parents.
         */
        private int applyDirectOverrides(Path projectPath, List<Vulnerability> vulnerabilities) {
            Path pom = projectPath.toAbsolutePath().normalize();
            if (java.nio.file.Files.isDirectory(pom)) {
                pom = pom.resolve("pom.xml");
            }

            List<Vulnerability> fixable = vulnerabilities.stream()
                    .filter(v -> v.getRemediationCandidate() != null && v.getRemediationCandidate().target() != null)
                    .toList();

            if (fixable.isEmpty()) return 0;

            try {
                String content = java.nio.file.Files.readString(pom, java.nio.charset.StandardCharsets.UTF_8);
                int applied = 0;

                for (Vulnerability v : fixable) {
                    ComponentCoordinate target = v.getRemediationCandidate().target();
                    String groupId = v.getGroupId();
                    String artifactId = v.getArtifactId();
                    String newVersion = target.version();

                    // Check if already in dependencyManagement
                    String gId = java.util.regex.Pattern.quote(groupId);
                    String aId = java.util.regex.Pattern.quote(artifactId);
                    if (content.matches("(?s).*<dependency>.*<groupId>\\s*" + gId + "\\s*</groupId>.*<artifactId>\\s*" + aId + "\\s*</artifactId>.*</dependency>.*")) {
                        continue; // already declared, skip
                    }

                    // Find insertion point: before </dependencies> in <dependencyManagement>
                    java.util.regex.Pattern dmPattern = java.util.regex.Pattern.compile(
                            "(<dependencyManagement>\\s*<dependencies>)(.*?)(</dependencies>\\s*</dependencyManagement>)",
                            java.util.regex.Pattern.DOTALL
                    );
                    java.util.regex.Matcher matcher = dmPattern.matcher(content);
                    if (!matcher.find()) continue;

                    String indent = "            ";
                    String newDep = "\n" + indent + "<dependency>\n"
                            + indent + "    <groupId>" + groupId + "</groupId>\n"
                            + indent + "    <artifactId>" + artifactId + "</artifactId>\n"
                            + indent + "    <version>" + newVersion + "</version>\n"
                            + indent + "</dependency>";

                    int insertPos = matcher.start(3);
                    content = content.substring(0, insertPos) + newDep + "\n" + indent + content.substring(insertPos);
                    applied++;
                    System.out.println("  OVERRIDE %s:%s → %s (inserted into dependencyManagement)".formatted(
                            groupId, artifactId, newVersion));
                }

                if (applied > 0) {
                    java.nio.file.Files.writeString(pom, content, java.nio.charset.StandardCharsets.UTF_8);
                    System.out.println("Applied %d direct override(s).".formatted(applied));
                }
                return applied;
            } catch (java.io.IOException e) {
                System.out.println("  ERROR: " + e.getMessage());
                return 0;
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

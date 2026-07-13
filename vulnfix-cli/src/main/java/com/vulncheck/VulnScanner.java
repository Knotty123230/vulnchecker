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
                description = "Sonatype application ID to scan. If not specified, searches by project directory name."
        )
        private String projectId;
        private final DependencyNodeFinder dependencyNodeFinder = new MavenDependencyNodeFinder();
        private final GraphGenerator graphGenerator = new GraphGenerator();


        @Override
        public void run() {
            VulnScannerConfiguration configuration = new VulnScannerConfigStore().load();

            // Resolve project ID if not specified
            if (projectId == null || projectId.isBlank()) {
                projectId = resolveProjectId(configuration);
                if (projectId == null) {
                    System.err.println("No application ID specified and could not auto-detect. Use --project-id");
                    return;
                }
            }

            DependencyNode dependencyNode = dependencyNodeFinder.find(path);
            if (dependencyNode == null) {
                System.err.println("Unable to resolve the Maven dependency graph; no changes were made.");
                return;
            }
            DependencyGraph graph = graphGenerator.generateGraph(dependencyNode);
            //TODO: here maven project, but can be gradle or other, then add other package managers
            VulnerabilitiesScanner sonatypeVulnerabilitiesScanner = new SonatypeVulnerabilitiesScanner(configuration.credentials());
            List<Vulnerability> vulnerabilities = sonatypeVulnerabilitiesScanner.scanDependencies(projectId, dependencyNode);

            printReport(vulnerabilities);
            printVersionConsistency(path, configuration.nexusRepository());
            printDeprecatedPackages(path, dependencyNode);

            ComponentVersionRepository versionRepository = configuration.nexusRepository() == null
                    ? ComponentVersionRepository.empty()
                    : new ResilientComponentVersionRepository(
                            new NexusComponentVersionRepository(configuration.nexusRepository()),
                            System.out::println
                    );
            if (configuration.nexusRepository() == null) {
                System.out.printf("Nexus is not configured; repository version fallback is disabled.%n");
            }
            List<PatchCandidate> candidates = new VulnerabilitiesFixer(vulnerabilities, graph, path, versionRepository)
                    .findPatchCandidates();

            System.out.println();
            System.out.printf("Found %d actionable patch candidate(s).%n", candidates.size());
            MavenPatchWorkflow patchWorkflow = new MavenPatchWorkflow(
                    new MavenPomPatcher(configuration.nexusRepository() != null
                            ? new PomDependencyFetcher(configuration.nexusRepository()) : null),
                    new MavenProjectBuildVerifier(configuration.nexusRepository()),
                    new SonatypePatchSecurityVerifier(
                            projectId, dependencyNodeFinder, sonatypeVulnerabilitiesScanner, vulnerabilities
                    ),
                    System.out::println
            );
            List<AppliedPatch> applied = patchWorkflow.applyRecommendedPatches(path, candidates);

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
                    System.out.println("No more semantically attributable patch candidates; manual review is required.");
                    break;
                }

                applied = patchWorkflow.applyRecommendedPatches(path, candidates);
                totalApplied += applied.size();

                if (applied.isEmpty()) {
                    System.out.println("No verified patches could be applied; unsafe direct overrides were not written.");
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
                System.out.printf("Dependency graph exported to %s%n", outputPath);
            }
        }

        /**
         * Resolves project ID by fuzzy-searching Sonatype IQ applications using the project directory name.
         */
        private String resolveProjectId(VulnScannerConfiguration configuration) {
            String BOLD = "\033[1m";
            String CYAN = "\033[0;36m";
            String GREEN = "\033[0;32m";
            String DIM = "\033[2m";
            String RESET = "\033[0m";

            SonatypeVulnerabilitiesScanner client = new SonatypeVulnerabilitiesScanner(configuration.credentials());
            String query = path.toAbsolutePath().normalize().getFileName().toString();
            System.out.println("Searching Sonatype IQ for '" + BOLD + query + RESET + "'...");

            List<String[]> allApps = client.listApplications();
            if (allApps.isEmpty()) {
                System.err.println("Failed to fetch applications from Sonatype IQ.");
                return null;
            }

            while (true) {
                String queryLower = query.toLowerCase();
                // Tokenize query for fuzzy matching
                String[] tokens = query.replaceAll("([a-z])([A-Z])", "$1 $2")
                        .replaceAll("[-_]+", " ").toLowerCase().split("\\s+");

                List<String[]> matches = allApps.stream()
                        .map(app -> {
                            String text = (app[0] + " " + app[1]).toLowerCase();
                            int score = 0;
                            for (String tok : tokens) {
                                if (tok.length() >= 2 && text.contains(tok)) score++;
                            }
                            if (text.contains(queryLower)) score += 10;
                            return new Object[]{score, app};
                        })
                        .filter(r -> (int) r[0] > 0)
                        .sorted((a, b) -> Integer.compare((int) b[0], (int) a[0]))
                        .limit(15)
                        .map(r -> (String[]) r[1])
                        .toList();

                if (matches.isEmpty()) {
                    System.out.println("  No matches for '" + query + "'");
                    System.out.print("  Enter search term (or exact app ID, 'q' to quit): ");
                    try {
                        java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(System.in));
                        query = reader.readLine();
                        if (query == null || query.trim().equalsIgnoreCase("q")) return null;
                        query = query.trim();
                        // Check if exact ID
                        String exactQuery = query;
                        if (allApps.stream().anyMatch(a -> a[0].equals(exactQuery))) return exactQuery;
                    } catch (java.io.IOException e) { return null; }
                    continue;
                }

                if (matches.size() == 1) {
                    String selected = matches.getFirst()[0];
                    System.out.println("  " + GREEN + "✓" + RESET + " Auto-selected: " + BOLD + selected + RESET
                            + " (" + matches.getFirst()[1] + ")");
                    return selected;
                }

                // Multiple matches — show list
                System.out.println();
                System.out.println(BOLD + "Select application:" + RESET);
                for (int i = 0; i < matches.size(); i++) {
                    System.out.printf("  %s%2d)%s %s  %s%s%s%n", CYAN, i + 1, RESET,
                            matches.get(i)[0], DIM, matches.get(i)[1], RESET);
                }
                System.out.println();
                System.out.print("  Number (or new search, 'q' to quit): ");
                try {
                    java.io.BufferedReader reader = new java.io.BufferedReader(new java.io.InputStreamReader(System.in));
                    String input = reader.readLine();
                    if (input == null || input.trim().equalsIgnoreCase("q")) return null;
                    input = input.trim();
                    if (input.matches("\\d+")) {
                        int idx = Integer.parseInt(input) - 1;
                        if (idx >= 0 && idx < matches.size()) {
                            String selected = matches.get(idx)[0];
                            System.out.println("  " + GREEN + "✓" + RESET + " Selected: " + BOLD + selected + RESET);
                            return selected;
                        }
                    }
                    query = input;
                } catch (java.io.IOException e) { return null; }
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
            return MavenReleaseLine.compatible(current, target);
        }

        private void printVersionConsistency(Path projectPath, NexusRepositoryConfiguration nexus) {
            String YELLOW = "\033[1;33m";
            String BOLD = "\033[1m";
            String DIM = "\033[2m";
            String RESET = "\033[0m";

            VersionConsistencyChecker.CompanionChecker companionChecker = null;
            if (nexus != null) {
                PomDependencyFetcher fetcher = new PomDependencyFetcher(nexus);
                companionChecker = fetcher::findCompanionArtifactIds;
            }
            var checker = new VersionConsistencyChecker(companionChecker);
            var inconsistencies = checker.check(projectPath);

            if (inconsistencies.isEmpty()) return;

            System.out.println();
            System.out.println(BOLD + "⚠ Version inconsistencies detected:" + RESET);
            for (var issue : inconsistencies) {
                if ("*".equals(issue.artifactId())) {
                    System.out.printf("  %s⚠%s %s:* — companion version mismatch:%s%n",
                            YELLOW, RESET, issue.groupId(), RESET);
                    issue.versionsBySection().forEach((artifact, version) ->
                            System.out.printf("    %s%s : %s%s%n", DIM, artifact, version, RESET));
                } else {
                    System.out.printf("  %s⚠%s %s:%s%n", YELLOW, RESET,
                            issue.groupId() + ":" + issue.artifactId(), RESET);
                    issue.versionsBySection().forEach((section, version) ->
                            System.out.printf("    %s%s → %s%s%n", DIM, section, version, RESET));
                }
            }
        }

        private void printDeprecatedPackages(Path projectPath, DependencyNode tree) {
            String RED = "\033[0;31m";
            String BOLD = "\033[1m";
            String DIM = "\033[2m";
            String GREEN = "\033[0;32m";
            String RESET = "\033[0m";

            var detector = new DeprecatedPackageDetector();
            var deprecated = detector.detect(projectPath);
            // Also check transitive
            var transitiveDeprecated = detector.detectInTree(tree);
            // Merge, dedup
            var all = new java.util.LinkedHashMap<String, DeprecatedPackageDetector.DeprecatedDependency>();
            for (var d : deprecated) all.putIfAbsent(d.groupId() + ":" + d.artifactId(), d);
            for (var d : transitiveDeprecated) all.putIfAbsent(d.groupId() + ":" + d.artifactId(), d);

            if (all.isEmpty()) return;

            System.out.println();
            System.out.println(BOLD + "⛔ Deprecated packages found:" + RESET);
            for (var d : all.values()) {
                System.out.printf("  %s✗%s %s:%s%s → %s%s:%s%s  %s(%s)%s%n",
                        RED, RESET,
                        d.groupId(), d.artifactId(),
                        d.version() != null ? ":" + d.version() : "",
                        GREEN, d.replacementGroupId(), d.replacementArtifactId(), RESET,
                        DIM, d.reason(), RESET);
            }
        }

        private void printReport(List<Vulnerability> vulnerabilities) {
            String RED = "\033[0;31m";
            String YELLOW = "\033[1;33m";
            String GREEN = "\033[0;32m";
            String BOLD = "\033[1m";
            String DIM = "\033[2m";
            String RESET = "\033[0m";

            System.out.println();
            System.out.println(BOLD + "Found " + vulnerabilities.size() + " vulnerable components" + RESET);
            System.out.println(DIM + "─".repeat(70) + RESET);

            int fixable = 0;
            int unfixable = 0;

            for (Vulnerability v : vulnerabilities) {
                RemediationCandidate remediation = v.getRemediationCandidate();

                String sevColor = switch (v.getSeverity() != null ? v.getSeverity().toLowerCase() : "") {
                    case "critical" -> RED;
                    case "severe" -> RED;
                    default -> YELLOW;
                };

                // Component line
                String component = v.getGroupId() + ":" + v.getArtifactId();
                System.out.printf("%n  %s●%s %s%s%s : %s", sevColor, RESET, BOLD, component, RESET, v.getVersion());

                if (remediation != null && remediation.target() != null) {
                    System.out.printf("  →  %s%s%s", GREEN, remediation.target().version(), RESET);
                    fixable++;

                    if (!remediation.directDependency() && remediation.parentCandidates() != null && !remediation.parentCandidates().isEmpty()) {
                        ComponentCoordinate parent = remediation.parentCandidates().getFirst();
                        System.out.printf("  %s(via %s:%s → %s)%s",
                                DIM, parent.groupId(), parent.artifactId(), parent.version(), RESET);
                    }
                } else {
                    System.out.printf("  %s(no fix available)%s", DIM, RESET);
                    unfixable++;
                }
                System.out.println();

                // CVE IDs inline
                String cves = String.join(", ", v.getCveIds());
                System.out.printf("    %s%s%s %s%s%s%n", sevColor, v.getSeverity() != null ? v.getSeverity().toUpperCase() : "?", RESET, DIM, cves, RESET);
            }

            // Summary
            System.out.println();
            System.out.println(DIM + "─".repeat(70) + RESET);
            System.out.printf("%s%d%s components affected, %s%s%d fixable%s, %s%d without fix%s%n",
                    BOLD, vulnerabilities.size(), RESET,
                    GREEN, BOLD, fixable, RESET,
                    DIM, unfixable, RESET);
            System.out.println();
        }
    }
}

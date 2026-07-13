package com.vulncheck;

import com.fasterxml.jackson.databind.JsonNode;

import java.util.*;

public class SonatypeVulnerabilitiesScanner implements VulnerabilitiesScanner {

    public static final String PKG_MANAGER = "maven";
    private final SonatypeClient sonatypeClient;
    private final RemediationCache cache = new RemediationCache();
    private static final List<String> REMEDIATION_PRIORITY = List.of(
            "recommended-non-breaking-with-dependencies",
            "recommended-non-breaking",
            "next-no-violations-with-dependencies",
            "next-no-violations",
            "next-non-failing-with-dependencies",
            "next-non-failing"
    );

    public SonatypeVulnerabilitiesScanner(SonatypeCredentials sonatypeCredentials) {
        this.sonatypeClient = new SonatypeClient(sonatypeCredentials);
    }

    /**
     * Lists all applications registered in Sonatype IQ.
     * @return list of [publicId, name] pairs
     */
    public List<String[]> listApplications() {
        return sonatypeClient.listApplications();
    }

    @Override
    public List<Vulnerability> scanDependencies(String projectId, DependencyNode dependencyNode) {
        Objects.requireNonNull(dependencyNode, "dependencyNode must not be null");
        if (isBlank(projectId)) {
            throw new IllegalArgumentException("projectId must not be blank");
        }

        String internalId = sonatypeClient.resolveInternalId(projectId);

        List<Vulnerability> rawVulnerabilities = toVulnerabilities(sonatypeClient.scan(internalId, toCycloneDxBom(dependencyNode)));

        // Merge by component: one Vulnerability per unique groupId:artifactId:version
        Map<String, Vulnerability> merged = new LinkedHashMap<>();
        for (Vulnerability v : rawVulnerabilities) {
            String key = v.getGroupId() + ":" + v.getArtifactId() + ":" + v.getVersion();
            Vulnerability existing = merged.get(key);
            if (existing == null) {
                merged.put(key, v);
            } else {
                existing.addCve(v.getId(), v.getSeverity());
            }
        }
        List<Vulnerability> vulnerabilities = new ArrayList<>(merged.values());

        // Fetch remediations in parallel — one per unique component
        try (var executor = java.util.concurrent.Executors.newVirtualThreadPerTaskExecutor()) {
            List<java.util.concurrent.Future<Void>> futures = vulnerabilities.stream()
                    .map(vulnerability -> executor.submit((java.util.concurrent.Callable<Void>) () -> {
                        DependencyNode vulnerableComponent = new DependencyNode(
                                vulnerability.getArtifactId(),
                                vulnerability.getGroupId(),
                                vulnerability.getVersion(),
                                null,
                                null
                        );
                        try {
                            Optional<RemediationCandidate> bestCandidate = findBestRemediation(internalId, vulnerableComponent);
                            bestCandidate.ifPresent(vulnerability::setRemediationCandidate);
                        } catch (Exception ignored) {
                        }
                        return null;
                    }))
                    .toList();

            for (var future : futures) {
                try { future.get(); } catch (Exception ignored) {}
            }
        }

        return vulnerabilities;
    }

    public Optional<RemediationCandidate> findBestRemediation(
            String applicationId,
            DependencyNode dependency
    ) {
        // Check disk cache first
        Optional<JsonNode> cached = cache.get(dependency.groupId(), dependency.artifactId(), dependency.version());
        JsonNode response;
        if (cached.isPresent()) {
            response = cached.get();
        } else {
            response = sonatypeClient.getRemediation(applicationId, dependency);
            cache.put(dependency.groupId(), dependency.artifactId(), dependency.version(), response);
        }

        List<RemediationCandidate> candidates =
                toRemediationCandidates(response);

        return selectBestCandidate(
                candidates,
                dependency.version()
        );
    }


    List<RemediationCandidate> toRemediationCandidates(JsonNode response) {
        if (response == null || response.isNull()) {
            return List.of();
        }

        JsonNode changes = response
                .path("remediation")
                .path("versionChanges");

        if (!changes.isArray()) {
            return List.of();
        }

        List<RemediationCandidate> result = new ArrayList<>();

        for (JsonNode change : changes) {
            JsonNode component = change
                    .path("data")
                    .path("component");

            ComponentCoordinate target = toCoordinate(component);

            if (target == null) {
                continue;
            }

            List<ComponentCoordinate> parents =
                    parseDirectDependencyData(change.path("directDependencyData"));

            result.add(new RemediationCandidate(
                    change.path("type").asText(null),
                    target,
                    change.path("directDependency").asBoolean(true),
                    parents
            ));
        }

        return List.copyOf(result);
    }

    private ComponentCoordinate toCoordinate(JsonNode component) {
        JsonNode coordinates = component
                .path("componentIdentifier")
                .path("coordinates");

        String groupId = coordinates.path("groupId").asText(null);
        String artifactId = coordinates.path("artifactId").asText(null);
        String version = coordinates.path("version").asText(null);

        if (isBlank(groupId) || isBlank(artifactId) || isBlank(version)) {
            return null;
        }

        return new ComponentCoordinate(
                groupId,
                artifactId,
                version
        );
    }


    private List<ComponentCoordinate> parseDirectDependencyData(JsonNode data) {
        if (!data.isArray()) {
            return List.of();
        }

        List<ComponentCoordinate> result = new ArrayList<>();

        for (JsonNode item : data) {
            ComponentCoordinate coordinate =
                    toCoordinate(item.path("component"));

            if (coordinate != null) {
                result.add(coordinate);
            }
        }

        return List.copyOf(result);
    }

    Optional<RemediationCandidate> selectBestCandidate(
            List<RemediationCandidate> candidates,
            String currentVersion
    ) {
        return candidates.stream()
                .filter(candidate ->
                        !currentVersion.equals(candidate.target().version())
                )
                .min(Comparator.comparingInt(candidate -> {
                    int index = REMEDIATION_PRIORITY.indexOf(candidate.type());
                    return index >= 0 ? index : Integer.MAX_VALUE;
                }));
    }


    private Map<String, Object> toCycloneDxBom(DependencyNode root) {
        Objects.requireNonNull(root, "root must not be null");

        Map<String, DependencyNode> componentsByRef = new LinkedHashMap<>();
        Map<String, Set<String>> relationships = new LinkedHashMap<>();

        collectGraph(root, componentsByRef, relationships);

        String rootRef = root.toPkg(PKG_MANAGER);

        List<Map<String, String>> components = componentsByRef.values().stream()
                .filter(node -> !node.toPkg(PKG_MANAGER).equals(rootRef))
                .map(this::toLibraryComponent)
                .toList();

        List<Map<String, Object>> dependencyRelationships = relationships.entrySet().stream()
                .map(entry -> Map.of(
                        "ref", entry.getKey(),
                        "dependsOn", List.copyOf(entry.getValue())
                ))
                .toList();

        return Map.of(
                "bomFormat", "CycloneDX",
                "specVersion", "1.5",
                "version", 1,
                "metadata", Map.of(
                        "component", toApplicationComponent(root)
                ),
                "components", components,
                "dependencies", dependencyRelationships
        );
    }

    private void collectGraph(
            DependencyNode node,
            Map<String, DependencyNode> components,
            Map<String, Set<String>> relationships
    ) {
        if (node == null) {
            return;
        }

        String nodeRef = node.toPkg(PKG_MANAGER);
        components.putIfAbsent(nodeRef, node);

        Set<String> childrenRefs = relationships.computeIfAbsent(
                nodeRef,
                ignored -> new LinkedHashSet<>()
        );

        if (node.children() == null) {
            return;
        }

        for (DependencyNode child : node.children()) {
            if (child == null) {
                continue;
            }

            String childRef = child.toPkg(PKG_MANAGER);
            childrenRefs.add(childRef);

            collectGraph(child, components, relationships);
        }
    }


    private Map<String, String> toLibraryComponent(DependencyNode node) {
        String purl = node.toPkg(PKG_MANAGER);

        return Map.of(
                "type", "library",
                "bom-ref", purl,
                "group", node.groupId(),
                "name", node.artifactId(),
                "version", node.version(),
                "purl", purl
        );
    }

    private Map<String, String> toApplicationComponent(DependencyNode node) {
        String purl = node.toPkg(PKG_MANAGER);

        return Map.of(
                "type", "application",
                "bom-ref", purl,
                "group", node.groupId(),
                "name", node.artifactId(),
                "version", node.version(),
                "purl", purl
        );
    }

    private List<Vulnerability> toVulnerabilities(JsonNode report) {
        if (report == null || report.isNull()) {
            return List.of();
        }

        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (JsonNode component : report.path("components")) {
            JsonNode coordinates = component
                    .path("componentIdentifier")
                    .path("coordinates");

            String groupId = coordinates.path("groupId").asText(null);
            String artifactId = coordinates.path("artifactId").asText(null);
            String version = coordinates.path("version").asText(null);

            for (JsonNode issue : component
                    .path("securityData")
                    .path("securityIssues")) {

                vulnerabilities.add(new Vulnerability(
                        firstPresent(issue, "reference", "id", "cve"),
                        groupId,
                        artifactId,
                        version,
                        firstPresent(issue, "threatCategory", "severity"),
                        firstPresent(issue, "description"),
                        firstPresent(issue, "url", "reference")
                ));
            }
        }

        return List.copyOf(vulnerabilities);
    }

    private String firstPresent(JsonNode node, String... paths) {
        for (String path : paths) {
            JsonNode candidate = node.at("/" + path.replace(".", "/"));

            if (candidate.isMissingNode() || candidate.isNull()) {
                continue;
            }

            String value = candidate.asText(null);

            if (value != null && !value.isBlank()) {
                return value;
            }
        }

        return null;
    }

    private boolean isBlank(String value) {
        return value == null || value.isBlank();
    }

}

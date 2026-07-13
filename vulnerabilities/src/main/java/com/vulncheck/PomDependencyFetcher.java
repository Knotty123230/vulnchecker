package com.vulncheck;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

/**
 * Fetches POM files from Nexus and parses declared dependencies.
 * Used to discover companion artifacts — dependencies that must share the same version.
 *
 * Algorithm:
 * 1. For each artifact in the project, fetch its POM from Nexus
 * 2. Parse POM dependencies
 * 3. If a project dependency has the same groupId as another project dep and
 *    appears in the POM's dependencies with version=${project.version} or exact version — they're companions
 */
public final class PomDependencyFetcher {

    public record PomDependency(String groupId, String artifactId, String version) {
        public boolean isProjectVersion() {
            return "${project.version}".equals(version)
                    || "${version}".equals(version);
        }
    }

    private final NexusRepositoryConfiguration config;
    private final HttpClient httpClient;
    private final ConcurrentMap<String, List<PomDependency>> cache = new ConcurrentHashMap<>();
    private final DocumentBuilderFactory domFactory;

    public PomDependencyFetcher(NexusRepositoryConfiguration config) {
        this.config = config;
        this.httpClient = HttpClient.newBuilder()
                .connectTimeout(config.requestTimeout())
                .build();
        this.domFactory = DocumentBuilderFactory.newInstance();
        try {
            domFactory.setNamespaceAware(false);
            domFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            domFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            domFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            domFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            domFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        } catch (Exception ignored) {}
    }

    /**
     * Fetches the POM for a given artifact and returns its declared dependencies.
     */
    public List<PomDependency> fetchDependencies(String groupId, String artifactId, String version) {
        String key = groupId + ":" + artifactId + ":" + version;
        return cache.computeIfAbsent(key, k -> doFetch(groupId, artifactId, version));
    }

    /**
     * Discovers companions for a given artifact by:
     * Checks only explicit same-group dependencies tied to ${project.version}.
     * Parent modules are paths rather than artifact IDs and are deliberately not guessed.
     */
    public List<String> findCompanionArtifactIds(String groupId, String artifactId, String version) {
        Set<String> companions = new LinkedHashSet<>();

        // 1. Check own POM dependencies
        List<PomDependency> deps = fetchDependencies(groupId, artifactId, version);
        for (PomDependency dep : deps) {
            if (dep.groupId().equals(groupId)) {
                if (dep.isProjectVersion()) {
                    companions.add(dep.artifactId());
                }
            }
        }

        companions.remove(artifactId); // don't include self
        return List.copyOf(companions);
    }

    private void addAuth(HttpRequest.Builder request) {
        if (config.bearerToken() != null && !config.bearerToken().isBlank()) {
            request.header("Authorization", "Bearer " + config.bearerToken());
        } else if (config.username() != null && config.password() != null) {
            String credentials = config.username() + ":" + config.password();
            request.header("Authorization", "Basic " +
                    Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8)));
        }
    }

    private List<PomDependency> doFetch(String groupId, String artifactId, String version) {
        String pomUrl = buildPomUrl(groupId, artifactId, version);
        try {
            HttpRequest.Builder request = HttpRequest.newBuilder()
                    .uri(URI.create(pomUrl))
                    .timeout(config.requestTimeout())
                    .GET();
            addAuth(request);

            HttpResponse<byte[]> response = httpClient.send(request.build(), HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() != 200) return List.of();

            return parsePomDependencies(response.body(), groupId);
        } catch (Exception e) {
            return List.of();
        }
    }

    private List<PomDependency> parsePomDependencies(byte[] pomBytes, String ownerGroupId) {
        try {
            Document doc = domFactory.newDocumentBuilder()
                    .parse(new ByteArrayInputStream(pomBytes));
            doc.normalizeDocument();

            List<PomDependency> result = new ArrayList<>();

            // Parse <dependencies> and <dependencyManagement><dependencies>
            NodeList depNodes = doc.getElementsByTagName("dependency");
            for (int i = 0; i < depNodes.getLength(); i++) {
                if (!(depNodes.item(i) instanceof Element dep)) continue;

                // Skip exclusion blocks (parent is <exclusions>)
                if (dep.getParentNode() != null &&
                        "exclusions".equals(dep.getParentNode().getNodeName())) continue;

                String g = text(dep, "groupId");
                String a = text(dep, "artifactId");
                String v = text(dep, "version");

                if (g != null && a != null) {
                    result.add(new PomDependency(g, a, v));
                }
            }
            return List.copyOf(result);
        } catch (Exception e) {
            return List.of();
        }
    }

    private String buildPomUrl(String groupId, String artifactId, String version) {
        // Nexus Maven proxy URL: <base>/repository/<repo>/<group>/<artifact>/<version>/<artifact>-<version>.pom
        String groupPath = groupId.replace('.', '/');
        String baseUrl = config.baseUrl().replaceAll("/+$", "");
        String repo = config.repository().replaceAll("/+$", "");
        return "%s/repository/%s/%s/%s/%s/%s-%s.pom"
                .formatted(baseUrl, repo, groupPath, artifactId, version, artifactId, version);
    }

    private String text(Element parent, String tag) {
        NodeList nodes = parent.getElementsByTagName(tag);
        if (nodes.getLength() == 0) return null;
        // Only direct child text, not nested
        for (int i = 0; i < nodes.getLength(); i++) {
            if (nodes.item(i).getParentNode() == parent) {
                String text = nodes.item(i).getTextContent();
                return text == null || text.isBlank() ? null : text.trim();
            }
        }
        return null;
    }
}

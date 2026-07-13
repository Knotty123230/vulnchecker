package com.vulncheck;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

/**
 * Detects version inconsistencies in pom.xml using DOM parsing.
 *
 * Two checks:
 * 1. Same artifact declared with different versions across sections (dependencyManagement vs dependencies)
 * 2. Pattern-based companion detection: artifacts with same groupId and same major version
 *    that have drifted to different specific versions
 *
 * When PomCompanionChecker (from vulnerabilities module) is attached, it also uses
 * Nexus POM fetching to discover true companions via ${project.version} declarations.
 */
public final class VersionConsistencyChecker {

    public record Inconsistency(
            String groupId,
            String artifactId,
            Map<String, String> versionsBySection,
            String message
    ) {}

    /** Optional callback to check companions via Nexus POM */
    private final CompanionChecker companionChecker;

    @FunctionalInterface
    public interface CompanionChecker {
        /** Returns companion artifactIds for given artifact that must share the same version */
        List<String> findCompanions(String groupId, String artifactId, String version);
    }

    public VersionConsistencyChecker() {
        this(null);
    }

    public VersionConsistencyChecker(CompanionChecker companionChecker) {
        this.companionChecker = companionChecker;
    }

    public List<Inconsistency> check(Path projectPath) {
        Path pom = projectPath.toAbsolutePath().normalize();
        if (Files.isDirectory(pom)) pom = pom.resolve("pom.xml");
        if (!Files.isRegularFile(pom)) return List.of();

        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(false);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            Document doc = factory.newDocumentBuilder().parse(pom.toFile());
            doc.normalizeDocument();

            Map<String, Map<String, String>> declared = collectDeclared(doc);
            List<Inconsistency> result = new ArrayList<>();

            checkDirectConflicts(declared, result);

            if (companionChecker != null) {
                checkCompanionsViaNexus(declared, result);
            } else {
                checkCompanionsByPattern(declared, result);
            }

            return result;
        } catch (Exception e) {
            return List.of();
        }
    }

    private Map<String, Map<String, String>> collectDeclared(Document doc) {
        Map<String, Map<String, String>> result = new LinkedHashMap<>();

        NodeList depLists = doc.getElementsByTagName("dependencies");
        for (int i = 0; i < depLists.getLength(); i++) {
            if (!(depLists.item(i) instanceof Element deps)) continue;

            String label = "dependencies";
            if (deps.getParentNode() instanceof Element p && "dependencyManagement".equals(p.getTagName())) {
                label = "dependencyManagement";
            }

            NodeList children = deps.getChildNodes();
            for (int j = 0; j < children.getLength(); j++) {
                if (!(children.item(j) instanceof Element dep)) continue;
                if (!"dependency".equals(dep.getTagName())) continue;
                // skip if inside <exclusions>
                if (dep.getParentNode() instanceof Element p2 && "exclusions".equals(p2.getTagName())) continue;

                String g = text(dep, "groupId");
                String a = text(dep, "artifactId");
                String v = text(dep, "version");

                if (g == null || a == null || v == null || v.contains("${")) continue;

                result.computeIfAbsent(g + ":" + a, k -> new LinkedHashMap<>()).put(label, v);
            }
        }
        return result;
    }

    private void checkDirectConflicts(Map<String, Map<String, String>> declared, List<Inconsistency> result) {
        for (var entry : declared.entrySet()) {
            Set<String> versions = new LinkedHashSet<>(entry.getValue().values());
            if (versions.size() > 1) {
                String[] parts = entry.getKey().split(":", 2);
                result.add(new Inconsistency(parts[0], parts[1],
                        Map.copyOf(entry.getValue()),
                        "Different versions in sections: " + entry.getValue()));
            }
        }
    }

    private void checkCompanionsViaNexus(Map<String, Map<String, String>> declared, List<Inconsistency> result) {
        Set<String> reported = new HashSet<>();
        result.forEach(i -> reported.add(i.groupId() + ":" + i.artifactId()));

        for (var entry : declared.entrySet()) {
            if (reported.contains(entry.getKey())) continue;
            String[] parts = entry.getKey().split(":", 2);
            String groupId = parts[0], artifactId = parts[1];
            String version = entry.getValue().values().stream().findFirst().orElse(null);
            if (version == null) continue;

            List<String> companions = companionChecker.findCompanions(groupId, artifactId, version);
            for (String companion : companions) {
                String ck = groupId + ":" + companion;
                if (!declared.containsKey(ck) || reported.contains(ck)) continue;
                String cv = declared.get(ck).values().stream().findFirst().orElse(null);
                if (cv != null && !cv.equals(version)) {
                    Map<String, String> details = new LinkedHashMap<>();
                    details.put(artifactId, version);
                    details.put(companion, cv);
                    result.add(new Inconsistency(groupId, "*", Map.copyOf(details),
                            "Companion mismatch (from " + artifactId + " POM: expects ${project.version})"));
                    reported.add(ck);
                }
            }
        }
    }

    private void checkCompanionsByPattern(Map<String, Map<String, String>> declared, List<Inconsistency> result) {
        Map<String, Map<String, String>> byGroup = new LinkedHashMap<>();
        for (var entry : declared.entrySet()) {
            String[] parts = entry.getKey().split(":", 2);
            String v = entry.getValue().values().stream().findFirst().orElse(null);
            if (v != null) byGroup.computeIfAbsent(parts[0], k -> new LinkedHashMap<>()).put(parts[1], v);
        }

        Set<String> reported = new HashSet<>();
        result.forEach(i -> reported.add(i.groupId()));

        for (var g : byGroup.entrySet()) {
            if (reported.contains(g.getKey()) || g.getValue().size() < 2) continue;
            Set<String> versions = new LinkedHashSet<>(g.getValue().values());
            if (versions.size() <= 1) continue;

            // Only report if same major (they're likely from same release)
            Set<String> majors = new HashSet<>();
            for (String v : versions) majors.add(v.contains(".") ? v.substring(0, v.indexOf('.')) : v);
            if (majors.size() == 1) {
                result.add(new Inconsistency(g.getKey(), "*",
                        Map.copyOf(g.getValue()),
                        "Possible companion version mismatch — consider aligning"));
            }
        }
    }

    private String text(Element parent, String tag) {
        NodeList nodes = parent.getElementsByTagName(tag);
        for (int i = 0; i < nodes.getLength(); i++) {
            if (nodes.item(i).getParentNode() == parent) {
                String t = nodes.item(i).getTextContent();
                return t == null || t.isBlank() ? null : t.trim();
            }
        }
        return null;
    }
}

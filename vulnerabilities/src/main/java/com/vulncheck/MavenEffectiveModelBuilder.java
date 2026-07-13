package com.vulncheck;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/** Builds version ownership and dependency provenance from Maven-generated project data. */
public final class MavenEffectiveModelBuilder {

    private static final Pattern MAVEN_SOURCE_COORDINATE = Pattern.compile(
            "([A-Za-z0-9_.-]+):([A-Za-z0-9_.-]+):(?:pom:)?([^,\\s]+)"
    );

    private final MavenCommandRunner mavenCommandRunner;
    private final ObjectMapper objectMapper;

    public MavenEffectiveModelBuilder() {
        this(new MavenInvokerCommandRunner(), new ObjectMapper());
    }

    public MavenEffectiveModelBuilder(MavenCommandRunner mavenCommandRunner, ObjectMapper objectMapper) {
        this.mavenCommandRunner = Objects.requireNonNull(mavenCommandRunner, "mavenCommandRunner must not be null");
        this.objectMapper = Objects.requireNonNull(objectMapper, "objectMapper must not be null");
    }

    public EffectiveMavenModel build(Path projectPath) {
        Path pom = resolvePom(projectPath);
        Path outputDirectory = pom.getParent().resolve("target/vulnchecker-analysis");
        Path effectivePom = outputDirectory.resolve("effective-pom.xml");
        Path dependencyTree = outputDirectory.resolve("dependency-tree.json");

        try {
            Files.createDirectories(outputDirectory);
            Files.deleteIfExists(effectivePom);
            Files.deleteIfExists(dependencyTree);
        } catch (IOException exception) {
            throw new MavenAnalysisException("Unable to prepare Maven analysis directory", exception);
        }

        mavenCommandRunner.generateModelAndDependencyTree(pom, effectivePom, dependencyTree);
        requireGeneratedFile(effectivePom);
        requireGeneratedFile(dependencyTree);

        PomView raw = readPom(pom, null);
        PomView effective = readPom(effectivePom, raw.project());
        List<ComponentCoordinate> importedBoms = raw.dependencyManagement().stream()
                .filter(PomDependency::isImportedBom)
                .map(dependency -> dependency.toCoordinate(raw.properties()))
                .filter(Objects::nonNull)
                .toList();

        return new EffectiveMavenModel(
                pom,
                effectivePom,
                effective.project(),
                importedBoms,
                resolveVersionOwners(pom, raw, effective, importedBoms),
                readDependencyPaths(dependencyTree)
        );
    }

    private List<VersionOwnerBinding> resolveVersionOwners(
            Path pom,
            PomView raw,
            PomView effective,
            List<ComponentCoordinate> importedBoms
    ) {
        Map<ComponentCoordinate, List<VersionOwner>> ownersByComponent = new LinkedHashMap<>();

        for (PomDependency managed : effective.dependencyManagement()) {
            if (managed.isImportedBom()) {
                continue;
            }
            ComponentCoordinate component = managed.toCoordinate(effective.properties());
            if (component == null) {
                continue;
            }
            List<VersionOwner> owners = declaredOwners(component, managed, pom, raw, importedBoms);
            if (!owners.isEmpty()) {
                ownersByComponent.computeIfAbsent(component, ignored -> new ArrayList<>()).addAll(owners);
            }
        }

        for (PomDependency dependency : effective.dependencies()) {
            ComponentCoordinate component = dependency.toCoordinate(effective.properties());
            if (component == null || ownersByComponent.containsKey(component)) {
                continue;
            }
            List<VersionOwner> owners = directOwners(component, pom, raw);
            if (!owners.isEmpty()) {
                ownersByComponent.put(component, owners);
            }
        }

        return ownersByComponent.entrySet().stream()
                .map(entry -> new VersionOwnerBinding(entry.getKey(), entry.getValue().stream().distinct().toList()))
                .toList();
    }

    private List<VersionOwner> declaredOwners(
            ComponentCoordinate component,
            PomDependency effectiveDeclaration,
            Path pom,
            PomView raw,
            List<ComponentCoordinate> importedBoms
    ) {
        List<VersionOwner> direct = directOwners(component, pom, raw);
        if (!direct.isEmpty()) {
            return direct;
        }

        PomDependency managed = findUniqueByGa(raw.dependencyManagement(), component);
        if (managed != null && !managed.isImportedBom()) {
            return List.of(ownerForDeclaration(
                    VersionOwnerType.DEPENDENCY_MANAGEMENT, component, managed.version(), pom, raw.properties()
            ));
        }

        ComponentCoordinate source = effectiveDeclaration.source();
        VersionOwner vo = new VersionOwner(VersionOwnerType.PARENT_POM, raw.parent(), null, pom);
        if (source != null) {
            ComponentCoordinate sourceBom = importedBoms.stream()
                    .filter(bom -> sameComponent(bom, source))
                    .findFirst()
                    .orElse(null);
            if (sourceBom != null) {
                return List.of(new VersionOwner(VersionOwnerType.IMPORTED_BOM, sourceBom, null, pom));
            }
            if (raw.parent() != null && sameComponent(raw.parent(), source)) {
                return List.of(vo);
            }
        }

        // A managed dependency can originate in only one effective declaration. When Maven
        // did not emit provenance, guessing every imported BOM and the parent creates unsafe
        // mutation points. Let the resolver fall back to an explicit upstream dependency.
        return List.of();
    }

    private boolean sameComponent(ComponentCoordinate first, ComponentCoordinate second) {
        return first.groupId().equals(second.groupId())
                && first.artifactId().equals(second.artifactId());
    }

    private List<VersionOwner> directOwners(ComponentCoordinate component, Path pom, PomView raw) {
        PomDependency direct = findUniqueByGa(raw.dependencies(), component);
        if (direct == null || direct.version() == null || direct.version().isBlank()) {
            return List.of();
        }
        return List.of(ownerForDeclaration(
                VersionOwnerType.DIRECT_DEPENDENCY, component, direct.version(), pom, raw.properties()
        ));
    }

    private VersionOwner ownerForDeclaration(
            VersionOwnerType defaultType,
            ComponentCoordinate component,
            String rawVersion,
            Path pom,
            Map<String, String> properties
    ) {
        String property = propertyName(rawVersion);
        if (property != null && properties.containsKey(property)) {
            return new VersionOwner(VersionOwnerType.LOCAL_PROPERTY, component, property, pom);
        }
        return new VersionOwner(defaultType, component, null, pom);
    }

    private PomDependency findUniqueByGa(List<PomDependency> dependencies, ComponentCoordinate component) {
        List<PomDependency> matches = dependencies.stream()
                .filter(dependency -> component.groupId().equals(dependency.groupId()))
                .filter(dependency -> component.artifactId().equals(dependency.artifactId()))
                .toList();
        return matches.size() == 1 ? matches.getFirst() : null;
    }

    private List<DependencyPath> readDependencyPaths(Path dependencyTree) {
        try {
            MavenDependencyTreeNode root = objectMapper.readValue(dependencyTree.toFile(), MavenDependencyTreeNode.class);
            List<DependencyPath> result = new ArrayList<>();
            collectPaths(root, List.of(), result);
            return List.copyOf(result);
        } catch (IOException exception) {
            throw new MavenAnalysisException("Unable to parse Maven dependency tree " + dependencyTree, exception);
        }
    }

    private void collectPaths(
            MavenDependencyTreeNode node,
            List<ComponentCoordinate> parentPath,
            List<DependencyPath> result
    ) {
        if (node == null || node.groupId() == null || node.artifactId() == null || node.version() == null) {
            return;
        }
        ComponentCoordinate component = new ComponentCoordinate(node.groupId(), node.artifactId(), node.version());
        List<ComponentCoordinate> path = new ArrayList<>(parentPath);
        path.add(component);
        result.add(new DependencyPath(component, path));

        if (node.children() != null) {
            node.children().forEach(child -> collectPaths(child, path, result));
        }
    }

    private PomView readPom(Path pom, ComponentCoordinate expectedProject) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            Document document = factory.newDocumentBuilder().parse(pom.toFile());
            Element project = selectProject(document.getDocumentElement(), expectedProject);

            ComponentCoordinate parent = coordinate(child(project, "parent"), Map.of());
            String groupId = text(project, "groupId");
            String artifactId = text(project, "artifactId");
            String version = text(project, "version");
            ComponentCoordinate projectCoordinate = new ComponentCoordinate(
                    groupId != null ? groupId : parent == null ? null : parent.groupId(),
                    artifactId,
                    version != null ? version : parent == null ? null : parent.version()
            );
            Map<String, String> properties = properties(child(project, "properties"));

            return new PomView(
                    projectCoordinate,
                    parent,
                    properties,
                    dependencies(child(project, "dependencies")),
                    dependencies(child(child(project, "dependencyManagement"), "dependencies"))
            );
        } catch (ParserConfigurationException | SAXException | IOException exception) {
            throw new MavenAnalysisException("Unable to parse POM " + pom, exception);
        }
    }

    private Element selectProject(Element root, ComponentCoordinate expectedProject) {
        if ("project".equals(root.getLocalName()) || "project".equals(root.getNodeName())) {
            return root;
        }

        List<Element> projects = children(root, "project");
        if (expectedProject == null) {
            return projects.stream().findFirst()
                    .orElseThrow(() -> new MavenAnalysisException("Effective POM contains no project"));
        }
        return projects.stream()
                .filter(project -> expectedProject.artifactId().equals(text(project, "artifactId")))
                .filter(project -> {
                    String groupId = text(project, "groupId");
                    Element parent = child(project, "parent");
                    String effectiveGroup = groupId != null ? groupId : text(parent, "groupId");
                    return expectedProject.groupId().equals(effectiveGroup);
                })
                .findFirst()
                .orElseThrow(() -> new MavenAnalysisException(
                        "Project " + expectedProject.groupId() + ":" + expectedProject.artifactId()
                                + " is absent from effective POM"
                ));
    }

    private Map<String, String> properties(Element propertiesElement) {
        if (propertiesElement == null) {
            return Map.of();
        }
        Map<String, String> result = new LinkedHashMap<>();
        for (Element property : children(propertiesElement, null)) {
            result.put(property.getLocalName() != null ? property.getLocalName() : property.getNodeName(), property.getTextContent().trim());
        }
        return Map.copyOf(result);
    }

    private List<PomDependency> dependencies(Element dependenciesElement) {
        if (dependenciesElement == null) {
            return List.of();
        }
        return children(dependenciesElement, "dependency").stream()
                .map(element -> new PomDependency(
                        text(element, "groupId"),
                        text(element, "artifactId"),
                        text(element, "version"),
                        text(element, "type"),
                        text(element, "scope"),
                        sourceCoordinate(element)
                ))
                .toList();
    }

    private ComponentCoordinate coordinate(Element element, Map<String, String> properties) {
        if (element == null) {
            return null;
        }
        return new PomDependency(
                text(element, "groupId"), text(element, "artifactId"), text(element, "version"), null, null, null
        ).toCoordinate(properties);
    }

    private ComponentCoordinate sourceCoordinate(Element element) {
        ComponentCoordinate nestedSource = sourceCoordinateFromComments(element);
        if (nestedSource != null) {
            return nestedSource;
        }

        Node sibling = element.getPreviousSibling();
        while (sibling != null) {
            if (sibling.getNodeType() == Node.COMMENT_NODE) {
                Matcher matcher = MAVEN_SOURCE_COORDINATE.matcher(sibling.getNodeValue());
                if (matcher.find()) {
                    return new ComponentCoordinate(matcher.group(1), matcher.group(2), matcher.group(3));
                }
            }
            if (sibling.getNodeType() == Node.ELEMENT_NODE) {
                break;
            }
            sibling = sibling.getPreviousSibling();
        }
        return null;
    }

    private ComponentCoordinate sourceCoordinateFromComments(Node node) {
        NodeList children = node.getChildNodes();
        for (int index = 0; index < children.getLength(); index++) {
            Node child = children.item(index);
            if (child.getNodeType() == Node.COMMENT_NODE) {
                Matcher matcher = MAVEN_SOURCE_COORDINATE.matcher(child.getNodeValue());
                if (matcher.find()) {
                    return new ComponentCoordinate(matcher.group(1), matcher.group(2), matcher.group(3));
                }
            }
            ComponentCoordinate nested = sourceCoordinateFromComments(child);
            if (nested != null) {
                return nested;
            }
        }
        return null;
    }

    private Element child(Element parent, String name) {
        if (parent == null) {
            return null;
        }
        return children(parent, name).stream().findFirst().orElse(null);
    }

    private List<Element> children(Element parent, String name) {
        List<Element> result = new ArrayList<>();
        NodeList nodes = parent.getChildNodes();
        for (int index = 0; index < nodes.getLength(); index++) {
            Node node = nodes.item(index);
            if (node instanceof Element element
                    && (name == null || name.equals(element.getLocalName()) || name.equals(element.getNodeName()))) {
                result.add(element);
            }
        }
        return result;
    }

    private String text(Element parent, String name) {
        Element value = child(parent, name);
        return value == null ? null : value.getTextContent().trim();
    }

    private Path resolvePom(Path projectPath) {
        Path normalized = projectPath.toAbsolutePath().normalize();
        Path pom = Files.isDirectory(normalized) ? normalized.resolve("pom.xml") : normalized;
        if (!Files.isRegularFile(pom)) {
            throw new MavenAnalysisException("pom.xml not found at " + pom);
        }
        return pom;
    }

    private void requireGeneratedFile(Path file) {
        if (!Files.isRegularFile(file)) {
            throw new MavenAnalysisException("Maven did not generate " + file);
        }
    }

    private static String propertyName(String value) {
        if (value == null || !value.startsWith("${") || !value.endsWith("}")) {
            return null;
        }
        return value.substring(2, value.length() - 1);
    }

    private record PomView(
            ComponentCoordinate project,
            ComponentCoordinate parent,
            Map<String, String> properties,
            List<PomDependency> dependencies,
            List<PomDependency> dependencyManagement
    ) {
    }

    private record PomDependency(
            String groupId,
            String artifactId,
            String version,
            String type,
            String scope,
            ComponentCoordinate source
    ) {
        boolean isImportedBom() {
            return "pom".equals(type) && "import".equals(scope);
        }

        ComponentCoordinate toCoordinate(Map<String, String> properties) {
            if (groupId == null || artifactId == null || version == null) {
                return null;
            }
            String property = propertyName(version);
            String resolvedVersion = property == null ? version : properties.get(property);
            return resolvedVersion == null
                    ? null
                    : new ComponentCoordinate(groupId, artifactId, resolvedVersion);
        }
    }
}

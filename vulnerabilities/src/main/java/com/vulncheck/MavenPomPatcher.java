package com.vulncheck;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.SAXException;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.List;

/** Applies one candidate to exactly one semantic location in the project's POM. */
public final class MavenPomPatcher {

    public MavenPomPatcher() {
    }

    /** Kept for source compatibility. Companion discovery is intentionally no longer used. */
    public MavenPomPatcher(PomDependencyFetcher ignored) {
    }

    public PomPatchTransaction apply(Path projectPath, PatchCandidate patchCandidate) {
        Path pom = resolvePom(projectPath, patchCandidate);
        byte[] original = read(pom);
        Document document = parse(pom);
        MutationPoint point = patchCandidate.mutationPoint();
        String newVersion = patchCandidate.candidate().replacement().coordinate().version();

        boolean changed = switch (point.type()) {
            case UPDATE_PROPERTY -> updateProperty(document, requireOwner(point).propertyName(), newVersion);
            case UPDATE_DIRECT_DEPENDENCY, UPDATE_PARENT_DEPENDENCY ->
                    updateDependency(document, point.component(), newVersion, DependencySection.DIRECT);
            case UPDATE_DEPENDENCY_MANAGEMENT ->
                    updateDependency(document, point.component(), newVersion, DependencySection.MANAGED);
            case UPDATE_IMPORTED_BOM ->
                    updateImportedBom(document, requireOwnerCoordinate(point), newVersion);
            case UPDATE_PARENT_POM -> updateParent(document, pom, requireOwnerCoordinate(point), newVersion);
        };

        if (!changed) {
            throw new PomPatchException("Mutation point " + point.type() + " was not found or already has version "
                    + newVersion + " in " + pom);
        }

        try {
            writeAtomically(pom, serialize(document));
            return new PomPatchTransaction(pom, original);
        } catch (RuntimeException exception) {
            restore(pom, original);
            throw exception;
        }
    }

    private VersionOwner requireOwner(MutationPoint point) {
        if (point.owner() == null) {
            throw new PomPatchException("Mutation point " + point.type() + " has no version owner");
        }
        return point.owner();
    }

    private ComponentCoordinate requireOwnerCoordinate(MutationPoint point) {
        VersionOwner owner = requireOwner(point);
        if (owner.coordinate() == null) {
            throw new PomPatchException("Mutation point " + point.type() + " has no owner coordinate");
        }
        return owner.coordinate();
    }

    private boolean updateProperty(Document document, String propertyName, String newVersion) {
        if (propertyName == null || propertyName.isBlank()) {
            return false;
        }
        Element properties = child(document.getDocumentElement(), "properties");
        Element property = child(properties, propertyName);
        return setVersion(property, newVersion);
    }

    private boolean updateDependency(
            Document document,
            ComponentCoordinate component,
            String newVersion,
            DependencySection section
    ) {
        Element project = document.getDocumentElement();
        Element dependencies = section == DependencySection.DIRECT
                ? child(project, "dependencies")
                : child(child(project, "dependencyManagement"), "dependencies");
        Element dependency = uniqueDependency(dependencies, component, false);
        return setDependencyVersion(document, dependency, newVersion);
    }

    private boolean updateImportedBom(Document document, ComponentCoordinate bom, String newVersion) {
        Element dependencies = child(child(document.getDocumentElement(), "dependencyManagement"), "dependencies");
        Element dependency = uniqueDependency(dependencies, bom, true);
        return setDependencyVersion(document, dependency, newVersion);
    }

    private boolean updateParent(
            Document document,
            Path childPom,
            ComponentCoordinate expectedParent,
            String newVersion
    ) {
        Element parent = child(document.getDocumentElement(), "parent");
        if (!matches(parent, expectedParent)) {
            return false;
        }
        rejectLocalParentUpgrade(parent, childPom, expectedParent);
        return setVersion(child(parent, "version"), newVersion);
    }

    private void rejectLocalParentUpgrade(Element parent, Path childPom, ComponentCoordinate expectedParent) {
        String configuredPath = text(parent, "relativePath");
        if (configuredPath != null && configuredPath.isEmpty()) {
            return;
        }
        String relativePath = configuredPath == null ? "../pom.xml" : configuredPath;
        Path localParent = childPom.getParent().resolve(relativePath).normalize();
        if (!Files.isRegularFile(localParent)) {
            return;
        }
        Document localDocument = parse(localParent);
        Element project = localDocument.getDocumentElement();
        if (expectedParent.groupId().equals(effectiveProjectGroupId(project))
                && expectedParent.artifactId().equals(text(project, "artifactId"))
                && expectedParent.version().equals(text(project, "version"))) {
            throw new PomPatchException("Refusing to change a local parent reference without atomically upgrading "
                    + localParent);
        }
    }

    private String effectiveProjectGroupId(Element project) {
        String groupId = text(project, "groupId");
        return groupId != null ? groupId : text(child(project, "parent"), "groupId");
    }

    private Element uniqueDependency(Element dependencies, ComponentCoordinate component, boolean importedBom) {
        if (dependencies == null || component == null) {
            return null;
        }
        List<Element> matches = new ArrayList<>();
        for (Element dependency : children(dependencies, "dependency")) {
            if (matches(dependency, component)
                    && (!importedBom || ("pom".equals(text(dependency, "type"))
                    && "import".equals(text(dependency, "scope"))))
                    && (importedBom || isDefaultJarDependency(dependency))) {
                matches.add(dependency);
            }
        }
        if (matches.size() > 1) {
            throw new PomPatchException("Ambiguous dependency declaration for "
                    + component.groupId() + ":" + component.artifactId());
        }
        return matches.isEmpty() ? null : matches.getFirst();
    }

    private boolean isDefaultJarDependency(Element dependency) {
        String type = text(dependency, "type");
        return text(dependency, "classifier") == null && (type == null || "jar".equals(type));
    }

    private boolean matches(Element element, ComponentCoordinate coordinate) {
        return element != null && coordinate != null
                && coordinate.groupId().equals(text(element, "groupId"))
                && coordinate.artifactId().equals(text(element, "artifactId"));
    }

    private boolean setDependencyVersion(Document document, Element dependency, String newVersion) {
        if (dependency == null) {
            return false;
        }
        Element version = child(dependency, "version");
        if (version == null) {
            version = document.createElementNS(dependency.getNamespaceURI(), "version");
            dependency.insertBefore(version, firstDependencyElementAfterVersion(dependency));
        }
        return setVersion(version, newVersion);
    }

    private Node firstDependencyElementAfterVersion(Element dependency) {
        for (String name : List.of("type", "classifier", "scope", "systemPath", "optional", "exclusions")) {
            Element element = child(dependency, name);
            if (element != null) {
                return element;
            }
        }
        return null;
    }

    private boolean setVersion(Element element, String newVersion) {
        if (element == null || newVersion == null || newVersion.isBlank()) {
            return false;
        }
        String current = element.getTextContent().trim();
        if (newVersion.equals(current)) {
            return false;
        }
        element.setTextContent(newVersion);
        return true;
    }

    private Document parse(Path pom) {
        try {
            DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            factory.setNamespaceAware(true);
            factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
            return factory.newDocumentBuilder().parse(pom.toFile());
        } catch (ParserConfigurationException | SAXException | IOException exception) {
            throw new PomPatchException("Unable to parse " + pom, exception);
        }
    }

    private String serialize(Document document) {
        try {
            TransformerFactory factory = TransformerFactory.newInstance();
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            var transformer = factory.newTransformer();
            transformer.setOutputProperty(OutputKeys.ENCODING, StandardCharsets.UTF_8.name());
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.setOutputProperty("{http://xml.apache.org/xslt}indent-amount", "2");
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(document), new StreamResult(writer));
            return writer.toString();
        } catch (TransformerException | IllegalArgumentException exception) {
            throw new PomPatchException("Unable to serialize patched POM", exception);
        }
    }

    private Element child(Element parent, String name) {
        return children(parent, name).stream().findFirst().orElse(null);
    }

    private List<Element> children(Element parent, String name) {
        if (parent == null) {
            return List.of();
        }
        List<Element> result = new ArrayList<>();
        NodeList nodes = parent.getChildNodes();
        for (int index = 0; index < nodes.getLength(); index++) {
            Node node = nodes.item(index);
            if (node instanceof Element element
                    && (name.equals(element.getLocalName()) || name.equals(element.getNodeName()))) {
                result.add(element);
            }
        }
        return result;
    }

    private String text(Element parent, String name) {
        Element element = child(parent, name);
        return element == null ? null : element.getTextContent().trim();
    }

    private byte[] read(Path pom) {
        try {
            return Files.readAllBytes(pom);
        } catch (IOException exception) {
            throw new PomPatchException("Unable to read " + pom, exception);
        }
    }

    private void writeAtomically(Path pom, String content) {
        Path temporary = null;
        try {
            temporary = Files.createTempFile(pom.getParent(), ".vulnchecker-", ".pom");
            Files.writeString(temporary, content, StandardCharsets.UTF_8);
            try {
                Files.move(temporary, pom, StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            } catch (AtomicMoveNotSupportedException ignored) {
                Files.move(temporary, pom, StandardCopyOption.REPLACE_EXISTING);
            }
        } catch (IOException exception) {
            throw new PomPatchException("Unable to write " + pom, exception);
        } finally {
            if (temporary != null) {
                try {
                    Files.deleteIfExists(temporary);
                } catch (IOException ignored) {
                }
            }
        }
    }

    private void restore(Path pom, byte[] content) {
        try {
            Files.write(pom, content);
        } catch (IOException ignored) {
        }
    }

    private Path resolvePom(Path projectPath, PatchCandidate candidate) {
        Path normalized = projectPath.toAbsolutePath().normalize();
        Path defaultPom = Files.isDirectory(normalized) ? normalized.resolve("pom.xml") : normalized;
        Path ownerPom = candidate.mutationPoint().owner() == null ? null : candidate.mutationPoint().owner().pomPath();
        Path pom = ownerPom != null && Files.isRegularFile(ownerPom) ? ownerPom.toAbsolutePath().normalize() : defaultPom;
        if (!Files.isRegularFile(pom)) {
            throw new PomPatchException("pom.xml not found at " + pom);
        }
        return pom;
    }

    private enum DependencySection {
        DIRECT,
        MANAGED
    }
}

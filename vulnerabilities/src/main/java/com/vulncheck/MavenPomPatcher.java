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
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/** Applies one candidate to the project's own pom.xml inside a rollback transaction. */
public final class MavenPomPatcher {

    public PomPatchTransaction apply(Path projectPath, PatchCandidate patchCandidate) {
        Path pom = resolvePom(projectPath);
        byte[] original = read(pom);
        Document document = readDocument(pom);
        Element project = document.getDocumentElement();
        MutationPoint point = patchCandidate.mutationPoint();
        String version = patchCandidate.candidate().replacement().coordinate().version();

        boolean changed = switch (point.type()) {
            case UPDATE_PROPERTY -> updateProperty(project, point.owner().propertyName(), version);
            case UPDATE_DIRECT_DEPENDENCY -> updateDependency(
                    child(project, "dependencies"), point.component(), version
            );
            case UPDATE_DEPENDENCY_MANAGEMENT -> updateDependency(
                    child(child(project, "dependencyManagement"), "dependencies"), point.component(), version
            );
            case UPDATE_IMPORTED_BOM -> updateDependency(
                    child(child(project, "dependencyManagement"), "dependencies"), point.owner().coordinate(), version
            );
            case UPDATE_PARENT_DEPENDENCY -> updateDependency(
                    child(project, "dependencies"), point.component(), version
            );
            case UPDATE_PARENT_POM -> updateParent(project, point.owner().coordinate(), version);
        };

        if (!changed) {
            throw new PomPatchException("Mutation point " + point.type() + " was not found in " + pom);
        }

        try {
            writeDocument(document, pom);
            return new PomPatchTransaction(pom, original);
        } catch (RuntimeException exception) {
            restore(pom, original, exception);
            throw exception;
        }
    }

    private boolean updateProperty(Element project, String propertyName, String version) {
        if (propertyName == null) {
            return false;
        }
        Element properties = child(project, "properties");
        Element property = child(properties, propertyName);
        if (property == null || version.equals(property.getTextContent().trim())) {
            return false;
        }
        property.setTextContent(version);
        return true;
    }

    private boolean updateParent(Element project, ComponentCoordinate owner, String version) {
        Element parent = child(project, "parent");
        if (!matches(parent, owner)) {
            return false;
        }
        return setVersion(parent, version);
    }

    private boolean updateDependency(Element dependencies, ComponentCoordinate component, String version) {
        if (dependencies == null) {
            return false;
        }
        for (Element dependency : children(dependencies, "dependency")) {
            if (matches(dependency, component) && setVersion(dependency, version)) {
                return true;
            }
        }
        return false;
    }

    private boolean matches(Element element, ComponentCoordinate coordinate) {
        return element != null
                && coordinate != null
                && coordinate.groupId().equals(text(element, "groupId"))
                && coordinate.artifactId().equals(text(element, "artifactId"));
    }

    private boolean setVersion(Element declaration, String version) {
        Element versionElement = child(declaration, "version");
        if (versionElement == null || version.equals(versionElement.getTextContent().trim())) {
            return false;
        }
        versionElement.setTextContent(version);
        return true;
    }

    private Document readDocument(Path pom) {
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

    private void writeDocument(Document document, Path pom) {
        try {
            TransformerFactory factory = TransformerFactory.newInstance();
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            var transformer = factory.newTransformer();
            transformer.setOutputProperty(OutputKeys.INDENT, "yes");
            transformer.transform(new DOMSource(document), new StreamResult(pom.toFile()));
        } catch (TransformerException exception) {
            throw new PomPatchException("Unable to write " + pom, exception);
        }
    }

    private byte[] read(Path pom) {
        try {
            return Files.readAllBytes(pom);
        } catch (IOException exception) {
            throw new PomPatchException("Unable to read " + pom, exception);
        }
    }

    private void restore(Path pom, byte[] content, RuntimeException originalFailure) {
        try {
            Files.write(pom, content);
        } catch (IOException restoreFailure) {
            originalFailure.addSuppressed(restoreFailure);
        }
    }

    private Path resolvePom(Path projectPath) {
        Path normalized = projectPath.toAbsolutePath().normalize();
        Path pom = Files.isDirectory(normalized) ? normalized.resolve("pom.xml") : normalized;
        if (!Files.isRegularFile(pom)) {
            throw new PomPatchException("pom.xml not found at " + pom);
        }
        return pom;
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
        Element value = child(parent, name);
        return value == null ? null : value.getTextContent().trim();
    }
}

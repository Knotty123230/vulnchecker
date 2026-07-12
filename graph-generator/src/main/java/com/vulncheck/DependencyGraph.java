package com.vulncheck;

import org.jgrapht.Graph;
import org.jgrapht.generate.CompleteGraphGenerator;
import org.jgrapht.graph.DefaultEdge;
import org.jgrapht.graph.SimpleWeightedGraph;
import org.jgrapht.nio.DefaultAttribute;
import org.jgrapht.nio.dot.DOTExporter;

import java.io.IOException;
import java.io.Writer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;
import java.util.Map;

public record DependencyGraph(
        Graph<DependencyNode, DefaultEdge> graph

) {

    public static DependencyGraph empty() {
        Graph<DependencyNode, DefaultEdge> completeGraph = new SimpleWeightedGraph<>(DefaultEdge.class);
        CompleteGraphGenerator<DependencyNode, DefaultEdge> completeGenerator
                = new CompleteGraphGenerator<>();
        completeGenerator.generateGraph(completeGraph);
        return new DependencyGraph(completeGraph);
    }


    public DependencyGraph(Graph<DependencyNode, DefaultEdge> graph) {
        this.graph = graph;
    }


    public void addNode(DependencyNode node) {
        graph.addVertex(node);
    }

    public void addEdge(DependencyNode from, DependencyNode to) {
        graph.addEdge(from, to);
        graph.addEdge(to, from);
    }

    public boolean containsNode(DependencyNode node) {
        return graph.containsVertex(node);
    }

    public boolean containsEdge(DependencyNode from, DependencyNode to) {
        return graph.containsEdge(from, to);
    }

    public Path exportSvg(Path dirPath) {
        try {
            Files.createDirectories(dirPath);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        var exporter = new DOTExporter<DependencyNode, DefaultEdge>(node -> Integer.toString(node.hashCode()));
        Path dotPath = dirPath.resolve("temp.dot");


        exporter.setVertexAttributeProvider(node -> Map.of("label", DefaultAttribute.createAttribute(node.toPkg("maven"))));
        try (Writer writer = java.nio.file.Files.newBufferedWriter(dotPath)) {
            exporter.exportGraph(graph, writer);
        } catch (Exception e) {
            throw new RuntimeException("Failed to export graph to DOT format", e);
        }

        try {
            var svg = DotToSvgConverter.convert(dotPath, dirPath.resolve("graph.svg"));
            Files.delete(dotPath);
            return svg;
        } catch (Exception e) {
            throw new RuntimeException("Failed to convert DOT to SVG", e);
        }
    }


    public String toString() {
        return graph.toString();
    }

    public Iterable<DependencyNode> findNodesByComponent(String component) {
        return () -> graph.vertexSet().stream()
                .filter(node -> node.toPkg("maven").equals(component))
                .iterator();
    }

    public Iterable<DependencyNode> findParentNodes(List<DependencyNode> nodes) {
        return () -> nodes.stream()
                .filter(node -> graph.degreeOf(node) > 0)
                .flatMap(node -> graph.incomingEdgesOf(node).stream())
                .map(graph::getEdgeSource)
                .iterator();
    }

    public Iterable<DependencyNode> findNodesByGroupId(String groupId) {
        return () -> graph.vertexSet().stream()
                .filter(node -> node.groupId().equals(groupId))
                .iterator();
    }

    public Iterable<DependencyNode> findNodesByGroupIdAndArtifactId(String groupId, String artifactId) {
        return () -> graph.vertexSet().stream()
                .filter(node -> node.groupId().equals(groupId) && node.artifactId().equals(artifactId))
                .iterator();
    }
}

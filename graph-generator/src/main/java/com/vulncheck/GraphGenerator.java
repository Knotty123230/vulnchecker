package com.vulncheck;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class GraphGenerator {


    Map<String, List<DependencyNode>> visitedNodes = new java.util.HashMap<>();


    public DependencyGraph generateGraph(DependencyNode rootNode) {
        DependencyGraph graph = DependencyGraph.empty();
        buildGraph(rootNode, graph);
        visitedNodes.clear();
        return graph;
    }


    public void buildGraph(DependencyNode node, DependencyGraph graph) {

        graph.addNode(node);
        if (visitedNodes.containsKey(node.toPkgWithouthash())) {
            List<DependencyNode> visited = visitedNodes.get(node.toPkgWithouthash());
            visited.forEach(it -> {
                graph.addEdge(it, node);
            });
        }

        List<DependencyNode> visited = visitedNodes.getOrDefault(node.toPkgWithouthash(), new ArrayList<>());
        visited.add(node);
        visitedNodes.put(node.toPkgWithouthash(), visited);
        for (DependencyNode child : node.children()) {
            graph.addNode(child);
            graph.addEdge(child, node);
            buildGraph(child, graph);
        }
    }
}

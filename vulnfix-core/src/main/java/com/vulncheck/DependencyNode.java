package com.vulncheck;

import java.util.List;
import java.util.Objects;

public record DependencyNode(
        String artifactId,
        String groupId,
        String version,
        String scope,
        List<DependencyNode> children
) {

    public void printNodes(int deps) {
        printNode("", true, deps);
    }

    private void printNode(String prefix, boolean isLast, int depth) {
        IO.println("%s%s%s".formatted(prefix, connector(isLast), displayName()));

        if (depth == 0 || children == null || children.isEmpty()) {
            return;
        }

        String childPrefix = prefix + (isLast ? "    " : "|   ");
        int nextDepth = depth < 0 ? -1 : depth - 1;

        for (int i = 0; i < children.size(); i++) {
            DependencyNode child = children.get(i);
            if (child == null) {
                continue;
            }

            child.printNode(childPrefix, i == children.size() - 1, nextDepth);
        }
    }

    public String toPkg() {
        return "%s:%s:%s".formatted(groupId, artifactId, version);
    }

    public String toPkgWithouthash() {
        return "%s:%s".formatted(groupId, artifactId);
    }


    private String displayName() {
        String coordinates = "%s:%s:%s".formatted(
                Objects.toString(groupId, "<unknown-group>"),
                Objects.toString(artifactId, "<unknown-artifact>"),
                Objects.toString(version, "<unknown-version>")
        );

        if (scope == null || scope.isBlank()) {
            return coordinates;
        }

        return "%s [%s]".formatted(coordinates, scope);
    }

    private static String connector(boolean isLast) {
        return isLast ? "\\-- " : "|-- ";
    }
}

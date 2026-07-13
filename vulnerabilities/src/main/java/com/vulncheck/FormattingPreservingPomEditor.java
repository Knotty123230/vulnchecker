package com.vulncheck;

import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.Deque;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

/** Applies text-node changes without serializing or reformatting the surrounding POM. */
final class FormattingPreservingPomEditor {

    String apply(String source, List<PomTextReplacement> replacements) {
        if (replacements.isEmpty()) {
            return source;
        }

        Map<ElementPath, PomTextReplacement> replacementsByPath = replacements.stream()
                .collect(Collectors.toMap(
                        replacement -> pathOf(replacement.element()),
                        replacement -> replacement,
                        (first, ignored) -> first,
                        LinkedHashMap::new
                ));
        if (replacementsByPath.size() != replacements.size()) {
            throw new PomPatchException("Multiple POM mutations resolved to the same XML element");
        }

        Map<ElementPath, ContentRange> ranges = locateElementContent(source, replacementsByPath.keySet());
        if (ranges.size() != replacementsByPath.size()) {
            throw new PomPatchException("Unable to locate every semantic mutation in the original POM text");
        }

        List<ResolvedReplacement> resolved = new ArrayList<>();
        replacementsByPath.forEach((path, replacement) -> resolved.add(resolve(
                source, ranges.get(path), replacement
        )));
        resolved.sort(Comparator.comparingInt(ResolvedReplacement::start).reversed());

        StringBuilder patched = new StringBuilder(source);
        for (ResolvedReplacement replacement : resolved) {
            patched.replace(replacement.start(), replacement.end(), replacement.text());
        }
        return patched.toString();
    }

    private ResolvedReplacement resolve(
            String source,
            ContentRange range,
            PomTextReplacement replacement
    ) {
        String rawContent = source.substring(range.start(), range.end());
        if (rawContent.indexOf('<') >= 0) {
            throw new PomPatchException("Refusing to replace a POM version containing nested XML markup");
        }

        int valueStart = 0;
        while (valueStart < rawContent.length() && Character.isWhitespace(rawContent.charAt(valueStart))) {
            valueStart++;
        }
        int valueEnd = rawContent.length();
        while (valueEnd > valueStart && Character.isWhitespace(rawContent.charAt(valueEnd - 1))) {
            valueEnd--;
        }

        String actual = rawContent.substring(valueStart, valueEnd);
        if (!actual.equals(replacement.expectedText())) {
            throw new PomPatchException("POM text changed after semantic analysis; expected '"
                    + replacement.expectedText() + "' but found '" + actual + "'");
        }

        return new ResolvedReplacement(
                range.start() + valueStart,
                range.start() + valueEnd,
                escapeXmlText(replacement.replacementText())
        );
    }

    private String escapeXmlText(String value) {
        return value.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;");
    }

    private Map<ElementPath, ContentRange> locateElementContent(String source, Set<ElementPath> targets) {
        Map<ElementPath, ContentRange> result = new HashMap<>();
        Map<String, Integer> rootChildCounts = new HashMap<>();
        Deque<OpenElement> stack = new ArrayDeque<>();
        int cursor = 0;

        while (cursor < source.length()) {
            int tagStart = source.indexOf('<', cursor);
            if (tagStart < 0) {
                break;
            }
            if (source.startsWith("<!--", tagStart)) {
                cursor = endOf(source, tagStart + 4, "-->");
                continue;
            }
            if (source.startsWith("<![CDATA[", tagStart)) {
                cursor = endOf(source, tagStart + 9, "]]>");
                continue;
            }
            if (source.startsWith("<?", tagStart)) {
                cursor = endOf(source, tagStart + 2, "?>");
                continue;
            }
            if (source.startsWith("<!", tagStart)) {
                cursor = endOf(source, tagStart + 2, ">");
                continue;
            }

            int tagEnd = findTagEnd(source, tagStart + 1);
            if (source.startsWith("</", tagStart)) {
                String closingName = localName(readName(source, tagStart + 2, tagEnd));
                if (stack.isEmpty()) {
                    throw malformedPom("Unexpected closing tag " + closingName);
                }
                OpenElement open = stack.pop();
                if (!open.localName().equals(closingName)) {
                    throw malformedPom("Closing tag " + closingName + " does not match " + open.localName());
                }
                if (targets.contains(open.path())) {
                    result.put(open.path(), new ContentRange(open.contentStart(), tagStart));
                }
                cursor = tagEnd + 1;
                continue;
            }

            String qualifiedName = readName(source, tagStart + 1, tagEnd);
            String localName = localName(qualifiedName);
            OpenElement parent = stack.peek();
            Map<String, Integer> siblingCounts = parent == null ? rootChildCounts : parent.childCounts();
            int siblingIndex = siblingCounts.merge(localName, 1, Integer::sum) - 1;
            ElementPath path = parent == null
                    ? new ElementPath(List.of(new PathSegment(localName, siblingIndex)))
                    : parent.path().append(new PathSegment(localName, siblingIndex));

            if (!isSelfClosing(source, tagStart, tagEnd)) {
                stack.push(new OpenElement(path, localName, tagEnd + 1, new HashMap<>()));
            }
            cursor = tagEnd + 1;
        }

        if (!stack.isEmpty()) {
            throw malformedPom("Unclosed tag " + stack.peek().localName());
        }
        return result;
    }

    private int findTagEnd(String source, int from) {
        char quote = 0;
        for (int index = from; index < source.length(); index++) {
            char character = source.charAt(index);
            if (quote != 0) {
                if (character == quote) {
                    quote = 0;
                }
            } else if (character == '\'' || character == '"') {
                quote = character;
            } else if (character == '>') {
                return index;
            }
        }
        throw malformedPom("Unclosed XML tag");
    }

    private String readName(String source, int from, int tagEnd) {
        int start = from;
        while (start < tagEnd && Character.isWhitespace(source.charAt(start))) {
            start++;
        }
        int end = start;
        while (end < tagEnd) {
            char character = source.charAt(end);
            if (Character.isWhitespace(character) || character == '/' || character == '>') {
                break;
            }
            end++;
        }
        if (start == end) {
            throw malformedPom("XML tag has no name");
        }
        return source.substring(start, end);
    }

    private String localName(String qualifiedName) {
        int separator = qualifiedName.indexOf(':');
        return separator < 0 ? qualifiedName : qualifiedName.substring(separator + 1);
    }

    private boolean isSelfClosing(String source, int tagStart, int tagEnd) {
        int index = tagEnd - 1;
        while (index > tagStart && Character.isWhitespace(source.charAt(index))) {
            index--;
        }
        return source.charAt(index) == '/';
    }

    private int endOf(String source, int from, String terminator) {
        int end = source.indexOf(terminator, from);
        if (end < 0) {
            throw malformedPom("Unclosed XML construct " + terminator);
        }
        return end + terminator.length();
    }

    private ElementPath pathOf(Element element) {
        Deque<PathSegment> segments = new ArrayDeque<>();
        Node current = element;
        while (current instanceof Element currentElement) {
            String name = elementName(currentElement);
            int index = 0;
            Node sibling = currentElement.getPreviousSibling();
            while (sibling != null) {
                if (sibling instanceof Element siblingElement && name.equals(elementName(siblingElement))) {
                    index++;
                }
                sibling = sibling.getPreviousSibling();
            }
            segments.addFirst(new PathSegment(name, index));
            current = currentElement.getParentNode();
        }
        return new ElementPath(List.copyOf(segments));
    }

    private String elementName(Element element) {
        return element.getLocalName() == null ? localName(element.getNodeName()) : element.getLocalName();
    }

    private PomPatchException malformedPom(String detail) {
        return new PomPatchException("Unable to preserve POM formatting: " + detail);
    }

    private record OpenElement(
            ElementPath path,
            String localName,
            int contentStart,
            Map<String, Integer> childCounts
    ) {
    }

    private record PathSegment(String name, int siblingIndex) {
    }

    private record ElementPath(List<PathSegment> segments) {
        private ElementPath append(PathSegment segment) {
            List<PathSegment> appended = new ArrayList<>(segments);
            appended.add(segment);
            return new ElementPath(List.copyOf(appended));
        }
    }

    private record ContentRange(int start, int end) {
    }

    private record ResolvedReplacement(int start, int end, String text) {
    }
}

record PomTextReplacement(Element element, String expectedText, String replacementText) {
}

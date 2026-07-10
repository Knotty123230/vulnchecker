package com.vulncheck;

import guru.nidi.graphviz.engine.Format;
import guru.nidi.graphviz.engine.Graphviz;
import guru.nidi.graphviz.model.MutableGraph;
import guru.nidi.graphviz.parse.Parser;

import java.io.IOException;
import java.nio.file.Path;

public class DotToSvgConverter {


    private DotToSvgConverter() {
    }


    public static Path convert(Path dotFile, Path output) {
        try {
            MutableGraph graph = new Parser().read(dotFile.toFile());
            Graphviz.fromGraph(graph)
                    .render(Format.SVG)
                    .toFile(output.toFile());
            return output;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

    }
}

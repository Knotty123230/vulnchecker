package com.vulncheck;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class MavenEffectiveModelBuilderTest {

    @TempDir
    Path projectDirectory;

    @Test
    void buildsVersionOwnersAndDependencyPathsFromMavenOutputs() throws IOException {
        Files.writeString(projectDirectory.resolve("pom.xml"), rawPom());
        MavenCommandRunner runner = (pom, effectivePom, dependencyTree) -> {
            try {
                Files.writeString(effectivePom, effectivePom());
                Files.writeString(dependencyTree, dependencyTree());
            } catch (IOException exception) {
                throw new MavenAnalysisException("fixture write failed", exception);
            }
        };

        EffectiveMavenModel model = new MavenEffectiveModelBuilder(runner, new ObjectMapper()).build(projectDirectory);

        assertEquals(2, model.importedBoms().size());
        VersionOwnerBinding nettyBinding = model.versionOwners().stream()
                .filter(binding -> binding.component().groupId().equals("io.netty"))
                .filter(binding -> binding.component().artifactId().equals("netty-handler"))
                .findFirst()
                .orElseThrow();
        assertEquals(3, nettyBinding.owners().size());
        assertEquals(2, nettyBinding.owners().stream()
                .filter(owner -> owner.type() == VersionOwnerType.IMPORTED_BOM)
                .count());
        assertTrue(nettyBinding.owners().stream()
                .anyMatch(owner -> owner.type() == VersionOwnerType.PARENT_POM));
        VersionOwnerBinding codecBinding = model.versionOwners().stream()
                .filter(binding -> binding.component().artifactId().equals("netty-codec-http"))
                .findFirst()
                .orElseThrow();
        assertEquals(1, codecBinding.owners().size());
        assertEquals("spring-boot-dependencies", codecBinding.owners().getFirst().coordinate().artifactId());

        DependencyPath nettyPath = model.dependencyPaths().stream()
                .filter(path -> path.component().artifactId().equals("netty-handler"))
                .findFirst()
                .orElseThrow();
        assertEquals("reactor-netty", nettyPath.introducedBy().artifactId());
        assertEquals(List.of("demo-app", "reactor-netty", "netty-handler"),
                nettyPath.path().stream().map(ComponentCoordinate::artifactId).toList());
        assertEquals(List.of(nettyPath), model.pathsTo(nettyPath.component()));
    }

    private String rawPom() {
        return """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <parent>
                    <groupId>org.springframework.boot</groupId>
                    <artifactId>spring-boot-starter-parent</artifactId>
                    <version>3.3.0</version>
                  </parent>
                  <groupId>com.example</groupId>
                  <artifactId>demo-app</artifactId>
                  <version>1.0.0</version>
                  <properties>
                    <spring-boot.version>3.3.0</spring-boot.version>
                    <company-platform.version>5.0.0</company-platform.version>
                  </properties>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>org.springframework.boot</groupId>
                        <artifactId>spring-boot-dependencies</artifactId>
                        <version>${spring-boot.version}</version>
                        <type>pom</type>
                        <scope>import</scope>
                      </dependency>
                      <dependency>
                        <groupId>com.example</groupId>
                        <artifactId>company-platform</artifactId>
                        <version>${company-platform.version}</version>
                        <type>pom</type>
                        <scope>import</scope>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                  <dependencies>
                    <dependency>
                      <groupId>io.projectreactor.netty</groupId>
                      <artifactId>reactor-netty</artifactId>
                    </dependency>
                  </dependencies>
                </project>
                """;
    }

    private String effectivePom() {
        return """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <parent>
                    <groupId>org.springframework.boot</groupId>
                    <artifactId>spring-boot-starter-parent</artifactId>
                    <version>3.3.0</version>
                  </parent>
                  <groupId>com.example</groupId>
                  <artifactId>demo-app</artifactId>
                  <version>1.0.0</version>
                  <dependencyManagement>
                    <dependencies>
                      <dependency>
                        <groupId>io.netty</groupId>
                        <artifactId>netty-handler</artifactId>
                        <version>4.1.100.Final</version>
                      </dependency>
                      <dependency>
                        <groupId>io.netty</groupId>
                        <!-- org.springframework.boot:spring-boot-dependencies:3.3.0, line 100 -->
                        <artifactId>netty-codec-http</artifactId>
                        <version>4.1.100.Final</version>
                      </dependency>
                    </dependencies>
                  </dependencyManagement>
                  <dependencies>
                    <dependency>
                      <groupId>io.projectreactor.netty</groupId>
                      <artifactId>reactor-netty</artifactId>
                      <version>1.1.0</version>
                    </dependency>
                  </dependencies>
                </project>
                """;
    }

    private String dependencyTree() {
        return """
                {
                  "groupId": "com.example",
                  "artifactId": "demo-app",
                  "version": "1.0.0",
                  "children": [{
                    "groupId": "io.projectreactor.netty",
                    "artifactId": "reactor-netty",
                    "version": "1.1.0",
                    "children": [{
                      "groupId": "io.netty",
                      "artifactId": "netty-handler",
                      "version": "4.1.100.Final",
                      "children": []
                    }]
                  }]
                }
                """;
    }
}

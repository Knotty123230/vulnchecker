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
        assertEquals(1, nettyBinding.owners().size());
        assertEquals(1, nettyBinding.owners().stream()
                .filter(owner -> owner.type() == VersionOwnerType.LOCAL_PROPERTY)
                .count());
        assertEquals("spring-boot.version", nettyBinding.owners().getFirst().propertyName());
        assertEquals("spring-boot-dependencies", nettyBinding.owners().getFirst().coordinate().artifactId());
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

    @Test
    void attributesInheritedManagedDependencyToRootParentWhenNoLocalBomCanOwnIt() throws IOException {
        Files.writeString(projectDirectory.resolve("pom.xml"), """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <parent>
                    <groupId>org.springframework.boot</groupId>
                    <artifactId>spring-boot-starter-parent</artifactId>
                    <version>3.5.14</version>
                  </parent>
                  <artifactId>demo-app</artifactId>
                </project>
                """);
        MavenCommandRunner runner = (pom, effectivePom, dependencyTree) -> {
            try {
                Files.writeString(effectivePom, """
                        <project xmlns="http://maven.apache.org/POM/4.0.0">
                          <modelVersion>4.0.0</modelVersion>
                          <parent>
                            <groupId>org.springframework.boot</groupId>
                            <artifactId>spring-boot-starter-parent</artifactId>
                            <version>3.5.14</version>
                          </parent>
                          <groupId>org.springframework.boot</groupId>
                          <artifactId>demo-app</artifactId>
                          <version>3.5.14</version>
                          <dependencyManagement>
                            <dependencies>
                              <dependency>
                                <groupId>org.springframework</groupId>
                                <!-- org.springframework.boot:spring-boot-dependencies:3.5.14, line 150 -->
                                <artifactId>spring-core</artifactId>
                                <version>6.2.18</version>
                              </dependency>
                            </dependencies>
                          </dependencyManagement>
                        </project>
                        """);
                Files.writeString(dependencyTree, """
                        {
                          "groupId": "org.springframework.boot",
                          "artifactId": "demo-app",
                          "version": "3.5.14",
                          "children": []
                        }
                        """);
            } catch (IOException exception) {
                throw new MavenAnalysisException("fixture write failed", exception);
            }
        };

        EffectiveMavenModel model = new MavenEffectiveModelBuilder(runner, new ObjectMapper()).build(projectDirectory);

        VersionOwner owner = model.versionOwners().stream()
                .filter(binding -> binding.component().artifactId().equals("spring-core"))
                .findFirst()
                .orElseThrow()
                .owners()
                .getFirst();
        assertEquals(VersionOwnerType.PARENT_POM, owner.type());
        assertEquals("spring-boot-starter-parent", owner.coordinate().artifactId());
        assertEquals("3.5.14", owner.coordinate().version());
    }

    @Test
    void treatsIdenticalDuplicateManagedEntriesAsOneLocalVersionOwner() throws IOException {
        Files.writeString(projectDirectory.resolve("pom.xml"), """
                <project xmlns="http://maven.apache.org/POM/4.0.0">
                  <modelVersion>4.0.0</modelVersion>
                  <groupId>com.example</groupId>
                  <artifactId>demo-app</artifactId>
                  <version>1.0.0</version>
                  <dependencyManagement><dependencies>
                    <dependency>
                      <groupId>org.springframework</groupId>
                      <artifactId>spring-core</artifactId>
                      <version>6.2.18</version>
                    </dependency>
                    <dependency>
                      <groupId>org.springframework</groupId>
                      <artifactId>spring-core</artifactId>
                      <version>6.2.18</version>
                    </dependency>
                  </dependencies></dependencyManagement>
                </project>
                """);
        MavenCommandRunner runner = (pom, effectivePom, dependencyTree) -> {
            try {
                Files.writeString(effectivePom, """
                        <project xmlns="http://maven.apache.org/POM/4.0.0">
                          <modelVersion>4.0.0</modelVersion>
                          <groupId>com.example</groupId>
                          <artifactId>demo-app</artifactId>
                          <version>1.0.0</version>
                          <dependencyManagement><dependencies>
                            <dependency>
                              <!-- com.example:demo-app:1.0.0, line 10 -->
                              <groupId>org.springframework</groupId>
                              <artifactId>spring-core</artifactId>
                              <version>6.2.18</version>
                            </dependency>
                          </dependencies></dependencyManagement>
                        </project>
                        """);
                Files.writeString(dependencyTree, """
                        {"groupId":"com.example","artifactId":"demo-app","version":"1.0.0","children":[]}
                        """);
            } catch (IOException exception) {
                throw new MavenAnalysisException("fixture write failed", exception);
            }
        };

        EffectiveMavenModel model = new MavenEffectiveModelBuilder(runner, new ObjectMapper()).build(projectDirectory);

        VersionOwner owner = model.versionOwners().getFirst().owners().getFirst();
        assertEquals(VersionOwnerType.DEPENDENCY_MANAGEMENT, owner.type());
        assertEquals("spring-core", owner.coordinate().artifactId());
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
                        <!-- org.springframework.boot:spring-boot-dependencies:3.3.0, line 99 -->
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

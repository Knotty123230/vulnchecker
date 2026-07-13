package com.vulncheck;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class PomDependencyFetcherTest {

    @Test
    void treatsVersionInheritedFromPublishedParentAsReleaseAligned() {
        var dependency = new PomDependencyFetcher.PomDependency(
                "ch.qos.logback", "logback-core", null
        );

        assertTrue(dependency.isAlignedWith("1.5.32"));
    }

    @Test
    void doesNotTreatDifferentExplicitVersionAsReleaseAligned() {
        var dependency = new PomDependencyFetcher.PomDependency(
                "com.example", "compatibility-module", "2.0.0"
        );

        assertFalse(dependency.isAlignedWith("1.0.0"));
    }
}

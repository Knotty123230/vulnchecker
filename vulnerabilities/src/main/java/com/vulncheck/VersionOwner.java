package com.vulncheck;

import java.nio.file.Path;

public record VersionOwner(
        VersionOwnerType type,
        ComponentCoordinate coordinate,
        String propertyName,
        Path pomPath
) {
}

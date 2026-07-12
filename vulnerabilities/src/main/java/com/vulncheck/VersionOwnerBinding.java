package com.vulncheck;

import java.util.List;

/** Associates a resolved component with the effective-model entries that own its version. */
public record VersionOwnerBinding(ComponentCoordinate component, List<VersionOwner> owners) {
    public VersionOwnerBinding {
        owners = List.copyOf(owners);
    }
}

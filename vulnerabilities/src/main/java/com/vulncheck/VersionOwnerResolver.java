package com.vulncheck;

import java.util.List;

public interface VersionOwnerResolver {
    List<VersionOwner> resolveOwners(ComponentCoordinate component, EffectiveMavenModel model);
}

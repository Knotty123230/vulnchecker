package com.vulncheck;

import java.util.List;

/** Resolves only owners explicitly present in the effective Maven model. */
public final class EffectiveModelVersionOwnerResolver implements VersionOwnerResolver {

    @Override
    public List<VersionOwner> resolveOwners(ComponentCoordinate component, EffectiveMavenModel model) {
        return model.ownersOf(component);
    }
}

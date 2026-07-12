package com.vulncheck;

import java.util.List;

public interface VersionSelectionPolicy {
    List<String> selectNewerVersions(String currentVersion, List<String> availableVersions);
}

package com.vulncheck;

/** Conservative compatibility boundary used only to decide whether an upgrade may be automatic. */
public final class MavenReleaseLine {

    private MavenReleaseLine() {
    }

    public static boolean compatible(String currentVersion, String targetVersion) {
        if (currentVersion == null || targetVersion == null) {
            return false;
        }
        return prefix(currentVersion).equals(prefix(targetVersion));
    }

    public static String prefix(String version) {
        String[] segments = version.split("[.-]");
        int numericSegments = 0;
        for (String segment : segments) {
            if (segment.matches("\\d+")) {
                numericSegments++;
            } else {
                break;
            }
        }
        if (numericSegments >= 4 || (numericSegments == 3 && segments.length > 3)) {
            int firstDot = version.indexOf('.');
            if (firstDot < 0) {
                return version;
            }
            int secondDot = version.indexOf('.', firstDot + 1);
            return secondDot > 0 ? version.substring(0, secondDot) : version;
        }
        int dot = version.indexOf('.');
        return dot > 0 ? version.substring(0, dot) : version;
    }
}

package com.vulncheck;

import java.util.List;

public interface CandidateGenerator {
    List<PatchCandidate> generate(
            MutationPoint mutationPoint,
            RemediationCandidate remediation,
            Vulnerability vulnerability
    );
}

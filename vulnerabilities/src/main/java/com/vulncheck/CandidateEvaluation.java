package com.vulncheck;

public record CandidateEvaluation(boolean accepted, int riskScore, String reason) {
    public static CandidateEvaluation accepted(int riskScore) {
        return new CandidateEvaluation(true, riskScore, null);
    }

    public static CandidateEvaluation rejected(String reason) {
        return new CandidateEvaluation(false, Integer.MAX_VALUE, reason);
    }
}

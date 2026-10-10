package com.socanalyzer.phishingdetector.model;

/** Severity levels used for every Finding. Drives both the UI badge color and the score impact. */
public enum Severity {
    LOW(5),
    MEDIUM(15),
    HIGH(30),
    CRITICAL(50);

    private final int defaultScoreImpact;

    Severity(int defaultScoreImpact) {
        this.defaultScoreImpact = defaultScoreImpact;
    }

    public int getDefaultScoreImpact() {
        return defaultScoreImpact;
    }
}

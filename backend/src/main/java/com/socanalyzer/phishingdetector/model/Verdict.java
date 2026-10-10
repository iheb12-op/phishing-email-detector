package com.socanalyzer.phishingdetector.model;

/** Final classification of an analyzed email, derived from the total risk score. */
public enum Verdict {
    SAFE,
    SUSPICIOUS,
    LIKELY_PHISHING,
    HIGH_CONFIDENCE_PHISHING;

    public static Verdict fromScore(int score) {
        if (score >= 75) return HIGH_CONFIDENCE_PHISHING;
        if (score >= 50) return LIKELY_PHISHING;
        if (score >= 25) return SUSPICIOUS;
        return SAFE;
    }
}

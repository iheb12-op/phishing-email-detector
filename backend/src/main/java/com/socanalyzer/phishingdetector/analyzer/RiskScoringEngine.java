package com.socanalyzer.phishingdetector.analyzer;

import com.socanalyzer.phishingdetector.config.ScoringWeightsProperties;
import com.socanalyzer.phishingdetector.model.Finding;
import com.socanalyzer.phishingdetector.model.Verdict;
import org.springframework.stereotype.Component;

import java.util.List;

/**
 * Transparent, additive risk scoring engine (requirement #10). The total
 * score is simply the sum of each Finding's scoreImpact (which itself
 * comes from the configurable per-severity weights), capped at maxScore.
 * The verdict is a pure function of the score against configurable
 * thresholds — never derived from a single "magic" indicator, which keeps
 * the whole pipeline explainable end-to-end.
 */
@Component
public class RiskScoringEngine {

    private final ScoringWeightsProperties weights;

    public RiskScoringEngine(ScoringWeightsProperties weights) {
        this.weights = weights;
    }

    public record ScoringResult(int totalScore, Verdict verdict) {}

    /** Applies configured weights to each finding's severity (overwriting the enum default) and sums them. */
    public ScoringResult score(List<Finding> findings) {
        int total = 0;
        for (Finding f : findings) {
            int impact = switch (f.getSeverity()) {
                case LOW -> weights.getLowWeight();
                case MEDIUM -> weights.getMediumWeight();
                case HIGH -> weights.getHighWeight();
                case CRITICAL -> weights.getCriticalWeight();
            };
            f.setScoreImpact(impact);
            total += impact;
        }
        total = Math.min(total, weights.getMaxScore());

        Verdict verdict;
        if (total >= weights.getLikelyPhishingThreshold()) {
            verdict = Verdict.HIGH_CONFIDENCE_PHISHING;
        } else if (total >= weights.getSuspiciousThreshold()) {
            verdict = Verdict.LIKELY_PHISHING;
        } else if (total >= weights.getSafeThreshold()) {
            verdict = Verdict.SUSPICIOUS;
        } else {
            verdict = Verdict.SAFE;
        }

        return new ScoringResult(total, verdict);
    }
}

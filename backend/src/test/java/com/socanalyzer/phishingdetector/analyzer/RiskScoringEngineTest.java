package com.socanalyzer.phishingdetector.analyzer;

import com.socanalyzer.phishingdetector.config.ScoringWeightsProperties;
import com.socanalyzer.phishingdetector.model.*;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RiskScoringEngineTest {

    private final RiskScoringEngine engine = new RiskScoringEngine(new ScoringWeightsProperties());

    @Test
    void emptyFindingsProduceSafeVerdict() {
        var result = engine.score(List.of());
        assertEquals(0, result.totalScore());
        assertEquals(Verdict.SAFE, result.verdict());
    }

    @Test
    void criticalFindingAloneReachesLikelyPhishingThreshold() {
        Finding f = new Finding(FindingCategory.ATTACHMENT_ANALYSIS, Severity.CRITICAL, "t", "d", "e", "r", 0, null);
        var result = engine.score(List.of(f));
        assertEquals(50, result.totalScore());
        assertEquals(Verdict.LIKELY_PHISHING, result.verdict());
    }

    @Test
    void scoreIsCappedAtMax() {
        List<Finding> many = List.of(
                new Finding(FindingCategory.URL_ANALYSIS, Severity.CRITICAL, "1", "d", "e", "r", 0, null),
                new Finding(FindingCategory.URL_ANALYSIS, Severity.CRITICAL, "2", "d", "e", "r", 0, null),
                new Finding(FindingCategory.URL_ANALYSIS, Severity.CRITICAL, "3", "d", "e", "r", 0, null)
        );
        var result = engine.score(many);
        assertEquals(100, result.totalScore());
        assertEquals(Verdict.HIGH_CONFIDENCE_PHISHING, result.verdict());
    }

    @Test
    void lowSeverityFindingsStaySafe() {
        Finding f = new Finding(FindingCategory.HEADER_ANALYSIS, Severity.LOW, "t", "d", "e", "r", 0, null);
        var result = engine.score(List.of(f));
        assertEquals(5, result.totalScore());
        assertEquals(Verdict.SAFE, result.verdict());
    }
}

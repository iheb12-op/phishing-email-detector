package com.socanalyzer.phishingdetector.dto;

import java.util.Map;

public record AnalysisStatsResponse(
        long totalAnalyses,
        Map<String, Long> verdictBreakdown,
        double averageRiskScore
) {}

package com.socanalyzer.phishingdetector.dto;

public record FindingDto(
        String id,
        String category,
        String severity,
        String title,
        String description,
        String evidence,
        String recommendation,
        int scoreImpact,
        String mitreTechniqueId
) {}

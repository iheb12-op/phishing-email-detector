package com.socanalyzer.phishingdetector.dto;

import java.time.Instant;
import java.util.List;

/** Full analysis result returned by the API and rendered by the SOC dashboard. */
public record AnalysisResponse(
        String id,
        Instant analyzedAt,
        int riskScore,
        String verdict,
        EmailOverviewDto emailOverview,
        AuthenticationSummaryDto authentication,
        List<FindingDto> findings,
        List<ExtractedUrlDto> urls,
        List<AttachmentDto> attachments,
        List<MitreMappingDto> mitreMappings,
        List<String> recommendedActions
) {}

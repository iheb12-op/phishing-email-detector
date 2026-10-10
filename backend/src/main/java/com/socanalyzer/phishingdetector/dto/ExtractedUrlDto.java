package com.socanalyzer.phishingdetector.dto;

public record ExtractedUrlDto(
        String id,
        String url,
        String domain,
        String risk,
        String reason,
        String displayedText,
        boolean domainMismatch,
        boolean usesIpAddress,
        boolean isShortener,
        boolean isPunycode,
        boolean usesHttps
) {}

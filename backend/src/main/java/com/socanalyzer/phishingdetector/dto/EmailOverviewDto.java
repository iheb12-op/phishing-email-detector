package com.socanalyzer.phishingdetector.dto;

public record EmailOverviewDto(
        String fromAddress,
        String fromDisplayName,
        String toAddress,
        String replyToAddress,
        String subject,
        String messageId,
        String date
) {}

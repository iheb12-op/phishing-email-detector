package com.socanalyzer.phishingdetector.dto;

public record AttachmentDto(
        String id,
        String filename,
        String declaredMimeType,
        long sizeBytes,
        String risk,
        String reason,
        boolean doubleExtension,
        boolean suspiciousExtension,
        boolean macroEnabled
) {}

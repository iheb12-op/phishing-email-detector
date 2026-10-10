package com.socanalyzer.phishingdetector.analyzer;

/** Attachment metadata only. Content bytes are intentionally NOT retained beyond parsing. */
public record ParsedAttachment(String filename, String declaredMimeType, long sizeBytes) {}

package com.socanalyzer.phishingdetector.model;

/** Categories a Finding can belong to, matching the analyzer that produced it. */
public enum FindingCategory {
    SENDER_ANALYSIS,
    HEADER_ANALYSIS,
    URL_ANALYSIS,
    DOMAIN_ANALYSIS,
    ATTACHMENT_ANALYSIS,
    HTML_ANALYSIS,
    CONTENT_ANALYSIS
}

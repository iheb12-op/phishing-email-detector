package com.socanalyzer.phishingdetector.analyzer;

import java.util.List;
import java.util.Map;

/**
 * Normalized, analyzer-friendly representation of an email, regardless of
 * whether it came from a raw .eml upload (parsed with Jakarta Mail) or
 * pasted plain text (parsed with a lightweight header regex fallback).
 * Every downstream analyzer (Header/Url/Domain/Attachment/Content/Html)
 * operates only on this object — never on raw bytes — so the untrusted
 * input is normalized exactly once.
 */
public record ParsedEmail(
        String fromRaw,            // full raw "From:" header, e.g. "PayPal Security <security@paypa1-example.com>"
        String fromAddress,
        String fromDisplayName,
        String toAddress,
        String replyToAddress,
        String returnPath,
        String subject,
        String messageId,
        String dateHeader,
        List<String> receivedChain,
        String authenticationResultsRaw,
        String textBody,
        String htmlBody,
        List<ParsedAttachment> attachments,
        Map<String, String> allHeaders
) {}

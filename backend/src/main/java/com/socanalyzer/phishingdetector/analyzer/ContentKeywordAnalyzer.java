package com.socanalyzer.phishingdetector.analyzer;

import com.socanalyzer.phishingdetector.model.Finding;
import com.socanalyzer.phishingdetector.model.FindingCategory;
import com.socanalyzer.phishingdetector.model.KeywordCategory;
import com.socanalyzer.phishingdetector.model.Severity;
import org.springframework.stereotype.Component;

import java.util.*;
import java.util.regex.Pattern;

/**
 * Detects social-engineering language in the email body (requirement #7).
 * Keywords NEVER produce a verdict on their own — they only contribute a
 * small amount of score, aggregated per category so a single finding is
 * produced per category instead of one per matched word (avoids inflating
 * the score for verbose, otherwise-benign emails).
 *
 * EDUCATIONAL NOTE:
 *  Attack: phishing relies on urgency and fear ("your account will be
 *  suspended", "act now") to short-circuit a victim's critical thinking —
 *  a classic social-engineering / persuasion technique, not a technical
 *  exploit.
 *  Why it matters: these phrases are cheap for attackers to write and
 *  effective, so they appear across nearly all phishing campaigns.
 *  False positives: legitimate security notifications, real password-reset
 *  emails, and genuine invoices use this exact language routinely — this is
 *  precisely why keyword matches are capped at LOW/MEDIUM score impact and
 *  never drive the verdict alone.
 *  SOC investigation: correlate keyword findings with technical indicators
 *  (auth failures, lookalike domains, link mismatches) before escalating.
 *  Remediation: user awareness training to recognize urgency-based
 *  manipulation regardless of how technically convincing the email looks.
 */
@Component
public class ContentKeywordAnalyzer {

    private static final Map<KeywordCategory, List<String>> KEYWORDS = Map.of(
            KeywordCategory.ACCOUNT_SECURITY, List.of("verify your account", "account suspended", "unusual login",
                    "security alert", "suspicious activity", "account locked"),
            KeywordCategory.PAYMENT, List.of("payment failed", "invoice", "wire transfer", "billing problem", "update your payment"),
            KeywordCategory.CREDENTIAL_THEFT, List.of("confirm your password", "password expired", "reset password",
                    "confirm identity", "enter your credentials", "login to verify"),
            KeywordCategory.URGENCY, List.of("urgent", "immediately", "act now", "click immediately", "within 24 hours", "final notice"),
            KeywordCategory.SOCIAL_ENGINEERING, List.of("confirm identity", "verify identity", "do not ignore", "this is not a scam"),
            KeywordCategory.DELIVERY, List.of("delivery failed", "package held", "shipment problem", "tracking number"),
            KeywordCategory.FINANCIAL_FRAUD, List.of("wire transfer", "gift card", "bitcoin", "tax refund", "you have won")
    );

    public List<Finding> analyze(String subject, String textBody, String htmlText) {
        List<Finding> findings = new ArrayList<>();
        String combined = ((subject != null ? subject : "") + " " +
                (textBody != null ? textBody : "") + " " +
                (htmlText != null ? htmlText : "")).toLowerCase();

        for (Map.Entry<KeywordCategory, List<String>> entry : KEYWORDS.entrySet()) {
            List<String> matched = new ArrayList<>();
            for (String kw : entry.getValue()) {
                if (containsWholeOrPhrase(combined, kw)) matched.add(kw);
            }
            if (!matched.isEmpty()) {
                Severity severity = matched.size() >= 3 ? Severity.MEDIUM : Severity.LOW;
                findings.add(new Finding(FindingCategory.CONTENT_ANALYSIS, severity,
                        entry.getKey().name().replace("_", " ") + " language detected",
                        "The email body contains language commonly associated with " +
                                entry.getKey().name().toLowerCase().replace("_", " ") + " phishing attempts.",
                        "Matched phrases: " + String.join(", ", matched),
                        "Do not act on urgency alone. Independently verify any request for credentials, payment, or personal information.",
                        severity.getDefaultScoreImpact(), null));
            }
        }
        return findings;
    }

    private boolean containsWholeOrPhrase(String haystack, String phrase) {
        // Simple substring match is sufficient here since phrases are multi-word;
        // Pattern.quote avoids regex injection from the keyword list itself.
        return Pattern.compile(Pattern.quote(phrase)).matcher(haystack).find();
    }
}

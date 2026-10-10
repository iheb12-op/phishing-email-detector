package com.socanalyzer.phishingdetector.analyzer;

import com.socanalyzer.phishingdetector.model.AuthResult;
import com.socanalyzer.phishingdetector.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class HeaderAnalyzerTest {

    private final HeaderAnalyzer analyzer = new HeaderAnalyzer();

    @Test
    void detectsSpfFailure() {
        ParsedEmail email = new ParsedEmail(null, "a@b.com", null, "c@d.com", null, null,
                "Subject", null, null, List.of(),
                "spf=fail dkim=pass dmarc=pass", "body", "", List.of(), Map.of());

        HeaderAnalyzer.HeaderAnalysisResult result = analyzer.analyze(email);

        assertEquals(AuthResult.FAIL, result.spf());
        assertTrue(result.findings().stream().anyMatch(f -> f.getTitle().contains("SPF")));
    }

    @Test
    void detectsReplyToDomainMismatch() {
        ParsedEmail email = new ParsedEmail(null, "security@paypal.com", "PayPal", "victim@d.com",
                "attacker@evil-domain.com", null, "Subject", null, null, List.of(),
                "spf=pass dkim=pass dmarc=pass", "body", "", List.of(), Map.of());

        HeaderAnalyzer.HeaderAnalysisResult result = analyzer.analyze(email);

        assertTrue(result.findings().stream()
                .anyMatch(f -> f.getTitle().contains("Reply-To") && f.getSeverity() == Severity.HIGH));
    }

    @Test
    void doesNotFlagWhenAuthenticationPasses() {
        ParsedEmail email = new ParsedEmail(null, "a@b.com", null, "c@b.com", "reply@b.com", null,
                "Subject", null, null, List.of(),
                "spf=pass dkim=pass dmarc=pass", "body", "", List.of(), Map.of());

        HeaderAnalyzer.HeaderAnalysisResult result = analyzer.analyze(email);

        assertTrue(result.findings().isEmpty());
    }
}

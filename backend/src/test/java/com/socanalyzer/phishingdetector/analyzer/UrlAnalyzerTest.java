package com.socanalyzer.phishingdetector.analyzer;

import com.socanalyzer.phishingdetector.config.TrustedDomainsProperties;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class UrlAnalyzerTest {

    private final DomainAnalyzer domainAnalyzer = new DomainAnalyzer(emptyTrusted());
    private final UrlAnalyzer analyzer = new UrlAnalyzer(domainAnalyzer);

    private static TrustedDomainsProperties emptyTrusted() {
        TrustedDomainsProperties p = new TrustedDomainsProperties();
        p.setDomains(List.of("example.com"));
        return p;
    }

    @Test
    void detectsDisplayedVsActualUrlMismatch() {
        String html = "<a href=\"https://malicious-example.com/login\">https://www.example.com</a>";
        ParsedEmail email = new ParsedEmail(null, null, null, null, null, null, "s", null, null,
                List.of(), null, "", html, List.of(), Map.of());

        UrlAnalyzer.UrlAnalysisResult result = analyzer.analyze(email);

        assertTrue(result.findings().stream()
                .anyMatch(f -> f.getTitle().contains("does not match")));
    }

    @Test
    void detectsIpAddressUrl() {
        ParsedEmail email = new ParsedEmail(null, null, null, null, null, null, "s", null, null,
                List.of(), null, "Visit http://192.0.2.55/reset-login now", "", List.of(), Map.of());

        UrlAnalyzer.UrlAnalysisResult result = analyzer.analyze(email);

        assertTrue(result.urls().stream().anyMatch(u -> u.isUsesIpAddress()));
    }

    @Test
    void detectsUrlShortener() {
        ParsedEmail email = new ParsedEmail(null, null, null, null, null, null, "s", null, null,
                List.of(), null, "Click http://bit.ly/3fakeXY", "", List.of(), Map.of());

        UrlAnalyzer.UrlAnalysisResult result = analyzer.analyze(email);

        assertTrue(result.urls().stream().anyMatch(u -> u.isShortener()));
    }

    @Test
    void manyUrlsAreAllExtracted() {
        StringBuilder body = new StringBuilder();
        for (int i = 0; i < 20; i++) body.append("http://example").append(i).append(".com/page\n");
        ParsedEmail email = new ParsedEmail(null, null, null, null, null, null, "s", null, null,
                List.of(), null, body.toString(), "", List.of(), Map.of());

        UrlAnalyzer.UrlAnalysisResult result = analyzer.analyze(email);

        assertEquals(20, result.urls().size());
    }
}

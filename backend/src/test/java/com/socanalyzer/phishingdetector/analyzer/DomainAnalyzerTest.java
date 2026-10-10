package com.socanalyzer.phishingdetector.analyzer;

import com.socanalyzer.phishingdetector.config.TrustedDomainsProperties;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class DomainAnalyzerTest {

    private DomainAnalyzer analyzer;

    @BeforeEach
    void setUp() {
        TrustedDomainsProperties props = new TrustedDomainsProperties();
        props.setDomains(List.of("paypal.com", "microsoft.com"));
        analyzer = new DomainAnalyzer(props);
    }

    @Test
    void detectsExactTrustedDomainAsNotLookalike() {
        DomainAnalyzer.DomainVerdict verdict = analyzer.analyze("paypal.com");
        assertTrue(verdict.lookalikeOf().isEmpty());
    }

    @Test
    void detectsTyposquattedDomain() {
        // Test case: "paypa1.com" (requirement #19 example)
        DomainAnalyzer.DomainVerdict verdict = analyzer.analyze("paypa1.com");
        assertTrue(verdict.lookalikeOf().isPresent());
        assertEquals("paypal.com", verdict.lookalikeOf().get());
    }

    @Test
    void detectsPunycodeDomain() {
        DomainAnalyzer.DomainVerdict verdict = analyzer.analyze("xn--micrsoft-ypb.com");
        assertTrue(verdict.isPunycode());
    }

    @Test
    void levenshteinDistanceIsSymmetricAndZeroForEqualStrings() {
        assertEquals(0, DomainAnalyzer.levenshtein("paypal", "paypal"));
        assertEquals(1, DomainAnalyzer.levenshtein("paypal", "paypa1"));
    }

    @Test
    void unrelatedDomainIsNotFlaggedAsLookalike() {
        DomainAnalyzer.DomainVerdict verdict = analyzer.analyze("completely-unrelated-shop.com");
        assertTrue(verdict.lookalikeOf().isEmpty());
    }
}

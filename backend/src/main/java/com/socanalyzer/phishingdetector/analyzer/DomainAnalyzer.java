package com.socanalyzer.phishingdetector.analyzer;

import com.socanalyzer.phishingdetector.config.TrustedDomainsProperties;
import org.springframework.stereotype.Component;

import java.net.IDN;
import java.util.List;
import java.util.Optional;

/**
 * Analyzes a single domain name for lookalike/typosquatting indicators
 * against a configurable trusted-domain list (requirement #6).
 *
 * EDUCATIONAL NOTE:
 *  Attack: typosquatting registers a domain that looks almost identical to
 *  a trusted one (paypa1.com, pay-pal-security.com, xn--pypal-4ve.com) to
 *  trick users who don't look closely at the address bar / From header.
 *  Why it matters: humans are bad at spotting single-character substitutions,
 *  especially with homoglyphs (0/O, 1/l, rn/m) or Unicode look-alikes
 *  encoded as punycode (xn--...).
 *  How detected: Levenshtein edit-distance against a trusted-domain list,
 *  plus explicit punycode (IDN) detection.
 *  False positives: legitimate regional or product sub-brands (e.g.
 *  "paypal-business.com" registered by PayPal itself) can trigger this.
 *  That's why this is a contributing indicator, not an automatic verdict.
 *  SOC investigation: check WHOIS registration date, registrar, and hosting
 *  provider reputation for the suspect domain.
 *  Remediation: defensive domain registration by brand owners; DNS
 *  monitoring services that alert on newly registered lookalike domains.
 */
@Component
public class DomainAnalyzer {

    private final TrustedDomainsProperties trustedDomainsProperties;

    public DomainAnalyzer(TrustedDomainsProperties trustedDomainsProperties) {
        this.trustedDomainsProperties = trustedDomainsProperties;
    }

    public record DomainVerdict(
            boolean isPunycode,
            String decodedUnicode,
            Optional<String> lookalikeOf,
            int editDistance,
            int subdomainCount,
            String tld,
            boolean containsSuspiciousKeyword
    ) {}

    public DomainVerdict analyze(String domain) {
        if (domain == null || domain.isBlank()) {
            return new DomainVerdict(false, null, Optional.empty(), -1, 0, "", false);
        }
        domain = domain.toLowerCase().trim();

        boolean isPunycode = domain.contains("xn--");
        String decoded = isPunycode ? safeIdnDecode(domain) : domain;

        String tld = extractTld(domain);
        int subdomainCount = Math.max(0, domain.split("\\.").length - 2);

        Optional<String> lookalikeOf = Optional.empty();
        int bestDistance = Integer.MAX_VALUE;
        List<String> trusted = trustedDomainsProperties.getDomains();
        if (trusted != null) {
            for (String trustedDomain : trusted) {
                if (domain.equalsIgnoreCase(trustedDomain)) {
                    bestDistance = 0;
                    lookalikeOf = Optional.empty(); // exact match to a trusted domain — not a lookalike
                    break;
                }
                int distance = levenshtein(stripTld(domain), stripTld(trustedDomain));
                // Small edit distance on an otherwise-different domain is the signature
                // of typosquatting (e.g. "paypa1" vs "paypal" = distance 1).
                if (distance > 0 && distance <= 2 && distance < bestDistance) {
                    bestDistance = distance;
                    lookalikeOf = Optional.of(trustedDomain);
                }
            }
        }

        boolean suspiciousKeyword = containsSuspiciousKeyword(domain);

        return new DomainVerdict(isPunycode, isPunycode ? decoded : null, lookalikeOf,
                lookalikeOf.isPresent() ? bestDistance : -1, subdomainCount, tld, suspiciousKeyword);
    }

    private String safeIdnDecode(String domain) {
        try {
            return IDN.toUnicode(domain);
        } catch (Exception e) {
            return domain; // never throw on malformed punycode — untrusted input
        }
    }

    private String extractTld(String domain) {
        String[] parts = domain.split("\\.");
        return parts.length > 0 ? parts[parts.length - 1] : "";
    }

    private String stripTld(String domain) {
        int lastDot = domain.lastIndexOf('.');
        int secondLastDot = domain.lastIndexOf('.', lastDot - 1);
        // keep just the registrable "core" label, e.g. "paypal" from "paypal.com"
        if (secondLastDot >= 0) return domain.substring(secondLastDot + 1, lastDot);
        if (lastDot >= 0) return domain.substring(0, lastDot);
        return domain;
    }

    private boolean containsSuspiciousKeyword(String domain) {
        String[] keywords = {"secure", "verify", "update", "account", "login", "signin", "confirm", "support-team"};
        for (String k : keywords) {
            if (domain.contains(k)) return true;
        }
        return false;
    }

    /** Classic Levenshtein edit distance, iterative DP implementation. */
    public static int levenshtein(String a, String b) {
        if (a == null) a = "";
        if (b == null) b = "";
        int[][] dp = new int[a.length() + 1][b.length() + 1];
        for (int i = 0; i <= a.length(); i++) dp[i][0] = i;
        for (int j = 0; j <= b.length(); j++) dp[0][j] = j;
        for (int i = 1; i <= a.length(); i++) {
            for (int j = 1; j <= b.length(); j++) {
                int cost = a.charAt(i - 1) == b.charAt(j - 1) ? 0 : 1;
                dp[i][j] = Math.min(Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1), dp[i - 1][j - 1] + cost);
            }
        }
        return dp[a.length()][b.length()];
    }
}

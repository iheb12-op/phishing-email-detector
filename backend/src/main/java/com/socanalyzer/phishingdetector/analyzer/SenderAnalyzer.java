package com.socanalyzer.phishingdetector.analyzer;

import com.socanalyzer.phishingdetector.config.TrustedDomainsProperties;
import com.socanalyzer.phishingdetector.model.Finding;
import com.socanalyzer.phishingdetector.model.FindingCategory;
import com.socanalyzer.phishingdetector.model.Severity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Analyzes the sender identity: does the display name claim to be a brand
 * that doesn't match the actual sending domain? This is a GENERIC mechanism
 * driven entirely by the configurable trusted-domain list — it is not
 * hardcoded to any single company (requirement #3).
 *
 * EDUCATIONAL NOTE:
 *  Attack: the attacker sets a display name like "PayPal Security" while the
 *  actual From address is security@paypa1-example.com. Most mail clients
 *  show only the display name by default, so victims never see the real
 *  address.
 *  Why it matters: this is one of the highest-signal, lowest-cost checks a
 *  detector can do — legitimate senders' display names almost always
 *  resolve to their own domain.
 *  False positives: personal assistants sending "on behalf of" a manager,
 *  or third-party notification services (e.g. "Jira <noreply@atlassian.net>"
 *  acting for a company) can look like a mismatch. Keep this a contributing
 *  signal, not a sole verdict.
 *  SOC investigation: cross-reference the sending domain against known
 *  legitimate mail providers for that brand (e.g. SPF includes).
 *  Remediation: user security awareness training on checking the real
 *  From address, and mail gateway rules that flag brand-name display names
 *  paired with unrelated sending domains.
 */
@Component
public class SenderAnalyzer {

    private final DomainAnalyzer domainAnalyzer;
    private final TrustedDomainsProperties trustedDomainsProperties;

    public SenderAnalyzer(DomainAnalyzer domainAnalyzer, TrustedDomainsProperties trustedDomainsProperties) {
        this.domainAnalyzer = domainAnalyzer;
        this.trustedDomainsProperties = trustedDomainsProperties;
    }

    public List<Finding> analyze(ParsedEmail email) {
        List<Finding> findings = new ArrayList<>();
        if (email.fromAddress() == null) return findings;

        String fromDomain = extractDomain(email.fromAddress());
        if (fromDomain == null) return findings;

        DomainAnalyzer.DomainVerdict verdict = domainAnalyzer.analyze(fromDomain);

        if (verdict.lookalikeOf().isPresent()) {
            findings.add(new Finding(FindingCategory.SENDER_ANALYSIS, Severity.HIGH,
                    "Sender domain resembles a trusted domain (possible lookalike)",
                    "The sending domain is very close (edit distance " + verdict.editDistance() +
                            ") to a known trusted domain, a common typosquatting technique.",
                    "Sender domain: " + fromDomain + " | Resembles: " + verdict.lookalikeOf().get(),
                    "Do not trust this sender. Verify through the organization's official, independently-known contact channel.",
                    Severity.HIGH.getDefaultScoreImpact(), "T1566.002"));
        }

        if (verdict.isPunycode()) {
            findings.add(new Finding(FindingCategory.SENDER_ANALYSIS, Severity.HIGH,
                    "Sender domain uses punycode / internationalized characters",
                    "The domain is encoded using punycode (xn--), which is often used to visually spoof trusted domains with look-alike Unicode characters.",
                    "Domain: " + fromDomain + (verdict.decodedUnicode() != null ? " | Decoded: " + verdict.decodedUnicode() : ""),
                    "Treat this sender as untrusted until independently verified.",
                    Severity.HIGH.getDefaultScoreImpact(), "T1566.002"));
        }

        // Display-name / domain mismatch: does the display name mention a trusted brand
        // whose domain differs from the actual sending domain?
        if (email.fromDisplayName() != null && trustedDomainsProperties.getDomains() != null) {
            String displayLower = email.fromDisplayName().toLowerCase();
            for (String trustedDomain : trustedDomainsProperties.getDomains()) {
                String brand = stripTld(trustedDomain);
                if (brand.length() >= 3 && displayLower.contains(brand) && !fromDomain.toLowerCase().contains(brand)) {
                    findings.add(new Finding(FindingCategory.SENDER_ANALYSIS, Severity.HIGH,
                            "Display name / domain mismatch",
                            "The display name references \"" + brand + "\" but the actual sending domain does not belong to that organization.",
                            "Display name: \"" + email.fromDisplayName() + "\" | Actual domain: " + fromDomain,
                            "Do not trust the display name. Inspect the raw From address and verify the sender independently.",
                            Severity.HIGH.getDefaultScoreImpact(), "T1566.002"));
                    break;
                }
            }
        }

        if (verdict.containsSuspiciousKeyword()) {
            findings.add(new Finding(FindingCategory.SENDER_ANALYSIS, Severity.LOW,
                    "Sender domain contains suspicious keywords",
                    "The sending domain contains words commonly used in phishing infrastructure (e.g. \"secure\", \"verify\", \"login\").",
                    "Domain: " + fromDomain,
                    "Treat as a weak signal; combine with other findings before drawing conclusions.",
                    Severity.LOW.getDefaultScoreImpact(), null));
        }

        return findings;
    }

    private String extractDomain(String address) {
        if (address == null) return null;
        int at = address.lastIndexOf('@');
        if (at < 0 || at == address.length() - 1) return null;
        return address.substring(at + 1).trim().replaceAll("[>\\s]", "");
    }

    private String stripTld(String domain) {
        int lastDot = domain.lastIndexOf('.');
        return lastDot > 0 ? domain.substring(0, lastDot) : domain;
    }
}

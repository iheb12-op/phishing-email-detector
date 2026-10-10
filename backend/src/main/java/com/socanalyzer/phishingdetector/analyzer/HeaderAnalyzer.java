package com.socanalyzer.phishingdetector.analyzer;

import com.socanalyzer.phishingdetector.model.AuthResult;
import com.socanalyzer.phishingdetector.model.Finding;
import com.socanalyzer.phishingdetector.model.FindingCategory;
import com.socanalyzer.phishingdetector.model.Severity;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Analyzes email headers: SPF/DKIM/DMARC authentication results, Reply-To
 * mismatches, and the Received chain.
 *
 * EDUCATIONAL NOTE (requirement #22):
 *  Attack: attackers spoof the "From" address so the email appears to come
 *  from a trusted sender. SPF/DKIM/DMARC are the three standard email
 *  authentication protocols that make spoofing detectable:
 *   - SPF  checks whether the sending mail server IP is authorized for the
 *          From domain.
 *   - DKIM checks a cryptographic signature proving the message wasn't
 *          altered in transit and was signed by the claimed domain.
 *   - DMARC tells receivers what to do when SPF/DKIM fail, and ties them to
 *          the visible From domain (alignment).
 *  Why it matters: a FAIL on any of these is a strong signal of spoofing,
 *  but NOT proof of phishing by itself — see false positives below.
 *  False positives: mailing lists, forwarded mail, and some legitimate bulk
 *  senders often show SPF/DKIM failures because the message passed through
 *  intermediate servers. That's why this engine only *contributes* score,
 *  it never auto-classifies on auth failure alone (requirement #4).
 *  SOC investigation: a real analyst would check the Received chain and the
 *  sending IP's reputation, not just the pass/fail flag.
 *  Remediation: domain owners should publish strict SPF/DKIM/DMARC (p=reject)
 *  records; defenders should quarantine/flag mail failing DMARC alignment.
 */
@Component
public class HeaderAnalyzer {

    private static final Pattern SPF_PATTERN = Pattern.compile("spf=(\\w+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern DKIM_PATTERN = Pattern.compile("dkim=(\\w+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern DMARC_PATTERN = Pattern.compile("dmarc=(\\w+)", Pattern.CASE_INSENSITIVE);

    public record HeaderAnalysisResult(AuthResult spf, AuthResult dkim, AuthResult dmarc, List<Finding> findings) {}

    public HeaderAnalysisResult analyze(ParsedEmail email) {
        List<Finding> findings = new ArrayList<>();

        AuthResult spf = extractAuthResult(email.authenticationResultsRaw(), SPF_PATTERN);
        AuthResult dkim = extractAuthResult(email.authenticationResultsRaw(), DKIM_PATTERN);
        AuthResult dmarc = extractAuthResult(email.authenticationResultsRaw(), DMARC_PATTERN);

        if (email.authenticationResultsRaw() == null || email.authenticationResultsRaw().isBlank()) {
            findings.add(new Finding(
                    FindingCategory.HEADER_ANALYSIS, Severity.LOW,
                    "Missing Authentication-Results header",
                    "No Authentication-Results header was present, so SPF/DKIM/DMARC status could not be verified.",
                    "Authentication-Results header: absent",
                    "Treat sender authenticity with caution; verify through an independent channel if the message requests sensitive action.",
                    Severity.LOW.getDefaultScoreImpact(), null));
        } else {
            if (spf == AuthResult.FAIL) {
                findings.add(new Finding(FindingCategory.HEADER_ANALYSIS, Severity.MEDIUM,
                        "SPF authentication failed",
                        "The sending server is not authorized to send mail for the claimed From domain according to SPF.",
                        "spf=fail (Authentication-Results header)",
                        "Verify the sender's identity through a separate, known-good channel before acting on this email.",
                        Severity.MEDIUM.getDefaultScoreImpact(), "T1566.002"));
            }
            if (dkim == AuthResult.FAIL) {
                findings.add(new Finding(FindingCategory.HEADER_ANALYSIS, Severity.MEDIUM,
                        "DKIM signature failed",
                        "The message's DKIM signature did not validate, suggesting it may have been altered or is not genuinely from the claimed domain.",
                        "dkim=fail (Authentication-Results header)",
                        "Do not trust attachments or links until the sender is verified independently.",
                        Severity.MEDIUM.getDefaultScoreImpact(), "T1566.002"));
            }
            if (dmarc == AuthResult.FAIL) {
                findings.add(new Finding(FindingCategory.HEADER_ANALYSIS, Severity.HIGH,
                        "DMARC alignment failed",
                        "The message failed DMARC, meaning it failed SPF or DKIM alignment against the visible From domain — a strong spoofing indicator.",
                        "dmarc=fail (Authentication-Results header)",
                        "Report to your security team; do not interact with links or attachments.",
                        Severity.HIGH.getDefaultScoreImpact(), "T1566.002"));
            }
        }

        // Reply-To mismatch: a classic BEC/phishing technique — replies go somewhere
        // other than the visible sender, redirecting the victim's response to the attacker.
        if (email.replyToAddress() != null && email.fromAddress() != null) {
            String replyDomain = extractDomain(email.replyToAddress());
            String fromDomain = extractDomain(email.fromAddress());
            if (replyDomain != null && fromDomain != null && !replyDomain.equalsIgnoreCase(fromDomain)) {
                findings.add(new Finding(FindingCategory.HEADER_ANALYSIS, Severity.HIGH,
                        "Reply-To domain mismatch",
                        "The Reply-To address points to a different domain than the From address. Replies would be redirected to an unexpected party.",
                        "From domain: " + fromDomain + " | Reply-To domain: " + replyDomain,
                        "Do not reply directly. Verify the sender through an independently known contact method.",
                        Severity.HIGH.getDefaultScoreImpact(), "T1566.002"));
            }
        }

        // Suspiciously short Received chain can indicate direct injection rather than
        // normal MTA-to-MTA relay (weak signal — kept LOW severity).
        if (email.receivedChain() != null && email.receivedChain().isEmpty() && email.authenticationResultsRaw() != null) {
            findings.add(new Finding(FindingCategory.HEADER_ANALYSIS, Severity.LOW,
                    "No Received headers present",
                    "The email has no Received header chain, which is unusual for mail delivered through standard infrastructure.",
                    "Received headers: none found",
                    "Inspect the message source manually if this email is under investigation.",
                    Severity.LOW.getDefaultScoreImpact(), null));
        }

        return new HeaderAnalysisResult(spf, dkim, dmarc, findings);
    }

    private AuthResult extractAuthResult(String raw, Pattern pattern) {
        if (raw == null) return AuthResult.UNKNOWN;
        Matcher m = pattern.matcher(raw);
        if (!m.find()) return AuthResult.UNKNOWN;
        String value = m.group(1).toUpperCase();
        try {
            return AuthResult.valueOf(value);
        } catch (IllegalArgumentException e) {
            return AuthResult.UNKNOWN;
        }
    }

    private String extractDomain(String address) {
        if (address == null) return null;
        int at = address.lastIndexOf('@');
        if (at < 0 || at == address.length() - 1) return null;
        return address.substring(at + 1).trim().replaceAll("[>\\s]", "");
    }
}

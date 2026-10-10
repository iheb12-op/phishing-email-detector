package com.socanalyzer.phishingdetector.analyzer;

import com.socanalyzer.phishingdetector.model.*;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.springframework.stereotype.Component;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Extracts and scores every URL found in a plain-text or HTML email body.
 *
 * SECURITY: this analyzer NEVER visits/fetches any URL. All indicators are
 * computed statically from the URL string and, for HTML links, the visible
 * anchor text — matching requirement #5's "safe by default" mandate.
 *
 * EDUCATIONAL NOTE:
 *  Attack: a phishing email's core payload is usually a link to a credential
 *  harvesting page. Attackers disguise the destination in several ways:
 *   - Displaying "https://www.realbank.com" as text while the href points
 *     elsewhere (classic HTML link spoofing).
 *   - Using URL shorteners to hide the real destination.
 *   - Using an IP address instead of a domain name.
 *   - Using punycode/IDN homoglyphs in the domain.
 *   - Stuffing an "@" into the URL so everything before it is ignored by
 *     the browser (http://real-bank.com@evil.tld/ actually goes to evil.tld).
 *  False positives: legitimate marketing emails often use tracking
 *  redirectors (e.g. link-tracking domains) that superficially resemble
 *  shorteners; that's why shortener usage alone is only a LOW/MEDIUM signal.
 *  SOC investigation: a defanged/sandboxed URL detonation service should be
 *  used to inspect the final destination — never a personal browser.
 *  Remediation: enforce a secure email gateway that rewrites/sandboxes all
 *  outbound links (e.g. "safe links" style protection).
 */
@Component
public class UrlAnalyzer {

    private static final Pattern URL_PATTERN = Pattern.compile(
            "(https?://[^\\s\"'<>]+)", Pattern.CASE_INSENSITIVE);

    private static final Set<String> KNOWN_SHORTENERS = Set.of(
            "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly", "cutt.ly");

    private static final Set<String> SUSPICIOUS_TLDS = Set.of(
            "zip", "mov", "xyz", "top", "tk", "gq", "ml", "cf", "ga", "click", "work", "link", "country");

    private final DomainAnalyzer domainAnalyzer;

    public UrlAnalyzer(DomainAnalyzer domainAnalyzer) {
        this.domainAnalyzer = domainAnalyzer;
    }

    public record UrlAnalysisResult(List<ExtractedUrl> urls, List<Finding> findings) {}

    public UrlAnalysisResult analyze(ParsedEmail email) {
        List<ParsedLink> links = extractLinks(email);
        List<ExtractedUrl> results = new ArrayList<>();
        List<Finding> findings = new ArrayList<>();

        for (ParsedLink link : links) {
            ExtractedUrl extracted = new ExtractedUrl();
            extracted.setUrl(truncate(link.href(), 2048));
            extracted.setDisplayedText(truncate(link.displayedText(), 500));

            URI uri = safeParse(link.href());
            String host = uri != null ? uri.getHost() : null;
            extracted.setDomain(host);
            extracted.setUsesHttps(link.href().toLowerCase().startsWith("https://"));

            Severity worstSeverity = null;
            List<String> reasons = new ArrayList<>();

            // 1. Displayed text vs actual href mismatch (HTML links only)
            if (link.fromHtml() && looksLikeUrl(link.displayedText())) {
                String displayedHost = extractHostFromText(link.displayedText());
                if (displayedHost != null && host != null && !displayedHost.equalsIgnoreCase(host)
                        && !host.toLowerCase().endsWith("." + displayedHost.toLowerCase())) {
                    extracted.setDomainMismatch(true);
                    reasons.add("Visible link destination does not match the displayed URL.");
                    worstSeverity = Severity.HIGH;
                    findings.add(new Finding(FindingCategory.URL_ANALYSIS, Severity.HIGH,
                            "Displayed URL does not match actual destination",
                            "The link text shown to the user does not match where the link actually points.",
                            "Visible domain: " + displayedHost + " | Actual destination: " + host,
                            "Do not open the link. Verify the sender through an independent channel.",
                            Severity.HIGH.getDefaultScoreImpact(), "T1566.002"));
                }
            }

            // 2. IP address instead of domain
            if (host != null && isIpAddress(host)) {
                extracted.setUsesIpAddress(true);
                reasons.add("URL uses a raw IP address instead of a domain name.");
                worstSeverity = maxSeverity(worstSeverity, Severity.HIGH);
                findings.add(new Finding(FindingCategory.URL_ANALYSIS, Severity.HIGH,
                        "URL uses an IP address instead of a domain",
                        "Legitimate services rarely link directly to a bare IP address; this is common in phishing/malware delivery infrastructure.",
                        "URL: " + truncate(link.href(), 200),
                        "Treat this link as untrusted. Do not enter any credentials if visited in a sandboxed environment.",
                        Severity.HIGH.getDefaultScoreImpact(), "T1566.002"));
            }

            // 3. URL shortener
            if (host != null && KNOWN_SHORTENERS.contains(host.toLowerCase())) {
                extracted.setShortener(true);
                reasons.add("URL uses a known link-shortening service, which hides the real destination.");
                worstSeverity = maxSeverity(worstSeverity, Severity.MEDIUM);
                findings.add(new Finding(FindingCategory.URL_ANALYSIS, Severity.MEDIUM,
                        "URL shortener detected",
                        "A link-shortening service is used, which obscures the true destination until clicked.",
                        "URL: " + truncate(link.href(), 200) + " | Shortener: " + host,
                        "Avoid clicking; if investigation is required, resolve the shortener in a sandboxed tool, never a personal browser.",
                        Severity.MEDIUM.getDefaultScoreImpact(), null));
            }

            // 4. Punycode / IDN domain
            if (host != null) {
                DomainAnalyzer.DomainVerdict domainVerdict = domainAnalyzer.analyze(host);
                if (domainVerdict.isPunycode()) {
                    extracted.setPunycode(true);
                    reasons.add("Domain uses punycode encoding, often used to spoof trusted domains visually.");
                    worstSeverity = maxSeverity(worstSeverity, Severity.HIGH);
                    findings.add(new Finding(FindingCategory.URL_ANALYSIS, Severity.HIGH,
                            "Punycode / lookalike domain in URL",
                            "The link domain is encoded as punycode, a technique used to visually mimic a trusted domain using Unicode look-alike characters.",
                            "Domain: " + host + (domainVerdict.decodedUnicode() != null ? " | Decoded: " + domainVerdict.decodedUnicode() : ""),
                            "Do not trust this link under any circumstances without independent domain verification.",
                            Severity.HIGH.getDefaultScoreImpact(), "T1566.002"));
                }
                if (domainVerdict.lookalikeOf().isPresent()) {
                    reasons.add("Domain closely resembles a trusted domain: " + domainVerdict.lookalikeOf().get());
                    worstSeverity = maxSeverity(worstSeverity, Severity.HIGH);
                    findings.add(new Finding(FindingCategory.URL_ANALYSIS, Severity.HIGH,
                            "Link domain resembles a trusted brand (lookalike)",
                            "The link domain is a near-match to a known trusted domain (edit distance " + domainVerdict.editDistance() + ").",
                            "Domain: " + host + " | Resembles: " + domainVerdict.lookalikeOf().get(),
                            "Do not open. Verify through the organization's official website typed manually.",
                            Severity.HIGH.getDefaultScoreImpact(), "T1566.002"));
                }
                String tld = domainVerdict.tld();
                if (SUSPICIOUS_TLDS.contains(tld)) {
                    reasons.add("URL uses a top-level domain frequently abused for phishing/malware (." + tld + ").");
                    worstSeverity = maxSeverity(worstSeverity, Severity.LOW);
                }
            }

            // 5. @ symbol trick
            if (link.href().contains("@") && uri != null) {
                reasons.add("URL contains an '@' symbol, which can be used to disguise the true destination host.");
                worstSeverity = maxSeverity(worstSeverity, Severity.MEDIUM);
                findings.add(new Finding(FindingCategory.URL_ANALYSIS, Severity.MEDIUM,
                        "URL contains '@' obfuscation",
                        "Everything before an '@' in a URL is ignored by browsers as userinfo, allowing attackers to disguise the real destination.",
                        "URL: " + truncate(link.href(), 200),
                        "Do not open. The real destination is the host after the '@' symbol.",
                        Severity.MEDIUM.getDefaultScoreImpact(), "T1566.002"));
            }

            // 6. Excessive URL length / encoded characters (weak heuristics)
            if (link.href().length() > 150) {
                reasons.add("Unusually long URL (" + link.href().length() + " characters).");
                worstSeverity = maxSeverity(worstSeverity, Severity.LOW);
            }
            long percentEncodedCount = countOccurrences(link.href(), '%');
            if (percentEncodedCount > 5) {
                reasons.add("URL contains excessive percent-encoded characters, which can be used to obfuscate the destination.");
                worstSeverity = maxSeverity(worstSeverity, Severity.LOW);
            }

            extracted.setRisk(worstSeverity != null ? worstSeverity : Severity.LOW);
            extracted.setReason(reasons.isEmpty() ? "No significant risk indicators detected." : String.join(" ", reasons));
            results.add(extracted);
        }

        return new UrlAnalysisResult(results, findings);
    }

    private List<ParsedLink> extractLinks(ParsedEmail email) {
        List<ParsedLink> links = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        if (email.htmlBody() != null && !email.htmlBody().isBlank()) {
            // Jsoup parses HTML as inert data only — no script execution, no network fetches.
            Document doc = Jsoup.parse(email.htmlBody());
            Elements anchors = doc.select("a[href]");
            for (Element a : anchors) {
                String href = a.attr("href");
                if (href.toLowerCase().startsWith("http")) {
                    String text = a.text().isBlank() ? href : a.text();
                    if (seen.add(href + "|" + text)) links.add(new ParsedLink(href, text, true));
                }
            }
        }

        String combinedText = (email.textBody() != null ? email.textBody() : "") +
                "\n" + (email.htmlBody() != null ? Jsoup.parse(email.htmlBody()).text() : "");
        Matcher m = URL_PATTERN.matcher(combinedText);
        while (m.find()) {
            String url = m.group(1);
            if (seen.add(url + "|" + url)) links.add(new ParsedLink(url, url, false));
        }

        return links;
    }

    private URI safeParse(String href) {
        try {
            return new URI(href);
        } catch (URISyntaxException e) {
            return null;
        }
    }

    private boolean looksLikeUrl(String text) {
        return text != null && (text.startsWith("http://") || text.startsWith("https://") || text.startsWith("www."));
    }

    private String extractHostFromText(String text) {
        try {
            String normalized = text.startsWith("http") ? text : "https://" + text;
            URI uri = new URI(normalized);
            return uri.getHost();
        } catch (Exception e) {
            return null;
        }
    }

    private boolean isIpAddress(String host) {
        return host.matches("^\\d{1,3}(\\.\\d{1,3}){3}$") || host.matches("^\\[?[0-9a-fA-F:]+]?$") && host.contains(":");
    }

    private Severity maxSeverity(Severity a, Severity b) {
        if (a == null) return b;
        if (b == null) return a;
        return a.ordinal() >= b.ordinal() ? a : b;
    }

    private String truncate(String s, int max) {
        if (s == null) return null;
        return s.length() <= max ? s : s.substring(0, max);
    }

    private long countOccurrences(String s, char c) {
        return s.chars().filter(ch -> ch == c).count();
    }
}

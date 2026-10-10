package com.socanalyzer.phishingdetector.analyzer;

import com.socanalyzer.phishingdetector.model.Finding;
import com.socanalyzer.phishingdetector.model.FindingCategory;
import com.socanalyzer.phishingdetector.model.Severity;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.parser.Parser;
import org.jsoup.select.Elements;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Analyzes HTML email structure for phishing/tracking techniques beyond
 * plain link extraction (requirement #9). Uses Jsoup's Parser.htmlParser()
 * which builds a DOM tree WITHOUT ever executing scripts or loading
 * external resources — HTML is treated purely as untrusted text/markup.
 *
 * EDUCATIONAL NOTE:
 *  Attack: phishing HTML emails often hide real links behind invisible
 *  elements (0px, display:none, opacity:0), embed remote tracking pixels to
 *  confirm a victim opened the email, or use <iframe> to load external
 *  attacker-controlled content inside the message.
 *  Why it matters: these are classic email-client-abuse techniques that
 *  predate and complement URL-based phishing.
 *  False positives: many legitimate marketing platforms (Mailchimp, etc.)
 *  also use 1x1 tracking pixels and hidden preheader text — that's why
 *  these are kept at LOW/MEDIUM severity rather than treated as proof of
 *  malicious intent.
 *  SOC investigation: view the email source (not rendered) to inspect
 *  hidden elements directly; check iframe src domains against threat intel.
 *  Remediation: mail clients that strip remote content / tracking pixels by
 *  default and block iframe rendering in email bodies.
 */
@Component
public class HtmlAnalyzer {

    public List<Finding> analyze(String htmlBody) {
        List<Finding> findings = new ArrayList<>();
        if (htmlBody == null || htmlBody.isBlank()) return findings;

        // Parser.htmlParser() only builds a DOM; it never executes <script> content.
        Document doc = org.jsoup.Jsoup.parse(htmlBody, "", Parser.htmlParser());

        Elements iframes = doc.select("iframe");
        if (!iframes.isEmpty()) {
            findings.add(new Finding(FindingCategory.HTML_ANALYSIS, Severity.MEDIUM,
                    "Iframe element in HTML email",
                    "The email embeds an <iframe>, which can load external content invisibly within the message.",
                    "Iframe count: " + iframes.size(),
                    "Do not interact with embedded content. View the email source rather than the rendered version if investigating.",
                    Severity.MEDIUM.getDefaultScoreImpact(), null));
        }

        Elements scripts = doc.select("script");
        if (!scripts.isEmpty()) {
            findings.add(new Finding(FindingCategory.HTML_ANALYSIS, Severity.HIGH,
                    "Embedded JavaScript in HTML email",
                    "The email contains <script> tags. Most modern mail clients block script execution, but this indicates an attempt to include active content.",
                    "Script tag count: " + scripts.size(),
                    "This finding is generated without executing the script. Report to security team for review in an isolated sandbox.",
                    Severity.HIGH.getDefaultScoreImpact(), null));
        }

        Elements hiddenElements = doc.select(
                "[style*=display:none], [style*=display: none], [style*=visibility:hidden], [style*=opacity:0]");
        if (!hiddenElements.isEmpty()) {
            findings.add(new Finding(FindingCategory.HTML_ANALYSIS, Severity.MEDIUM,
                    "Hidden elements detected in HTML email",
                    "The email contains elements deliberately hidden from view (display:none / opacity:0), sometimes used to hide malicious links from visual inspection while remaining machine-readable.",
                    "Hidden element count: " + hiddenElements.size(),
                    "Inspect the raw HTML source rather than the rendered email when investigating.",
                    Severity.MEDIUM.getDefaultScoreImpact(), null));
        }

        Elements forms = doc.select("form");
        if (!forms.isEmpty()) {
            findings.add(new Finding(FindingCategory.HTML_ANALYSIS, Severity.HIGH,
                    "Embedded form in HTML email",
                    "The email contains an HTML <form>, which can be used to collect credentials or personal data directly within the email client.",
                    "Form count: " + forms.size(),
                    "Never submit data into a form embedded in an email. Legitimate services do not request credentials this way.",
                    Severity.HIGH.getDefaultScoreImpact(), "T1566.002"));
        }

        // 1x1 tracking pixel detection
        Elements images = doc.select("img");
        long trackingPixels = images.stream().filter(img -> {
            String w = img.attr("width");
            String h = img.attr("height");
            return ("1".equals(w) && "1".equals(h));
        }).count();
        if (trackingPixels > 0) {
            findings.add(new Finding(FindingCategory.HTML_ANALYSIS, Severity.LOW,
                    "Tracking pixel detected",
                    "The email contains a 1x1 pixel image, commonly used to confirm the email was opened (open-tracking).",
                    "Tracking pixel count: " + trackingPixels,
                    "Disable automatic remote image loading in your mail client to prevent open-tracking confirmation.",
                    Severity.LOW.getDefaultScoreImpact(), null));
        }

        return findings;
    }
}

package com.socanalyzer.phishingdetector.analyzer;

import com.socanalyzer.phishingdetector.model.EmailAttachment;
import com.socanalyzer.phishingdetector.model.Finding;
import com.socanalyzer.phishingdetector.model.FindingCategory;
import com.socanalyzer.phishingdetector.model.Severity;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Analyzes declared attachment metadata (filename, MIME type, size).
 * Attachment CONTENT is never opened, executed, or scanned byte-for-byte —
 * only what the email itself declares, treated as untrusted claims
 * (requirement #8/#17).
 *
 * EDUCATIONAL NOTE:
 *  Attack: malicious executables are disguised with double extensions
 *  (invoice.pdf.exe) or delivered as macro-enabled Office documents that
 *  run code when opened ("enable content" social engineering).
 *  Why it matters: Windows Explorer hides known extensions by default, so
 *  "invoice.pdf.exe" may display to a victim as just "invoice.pdf".
 *  False positives: some legitimate business file names legitimately
 *  contain multiple dots (e.g. "report.v2.xlsx") — the double-extension
 *  check specifically looks for an executable extension following any
 *  other extension, not just any extra dot.
 *  SOC investigation: submit the file hash (never the file itself from an
 *  unmanaged machine) to a malware sandbox / threat intel platform.
 *  Remediation: mail gateways should block or quarantine executable
 *  attachment types outright, and disable macros by default org-wide.
 */
@Component
public class AttachmentAnalyzer {

    private static final Set<String> SUSPICIOUS_EXTENSIONS = Set.of(
            "exe", "scr", "bat", "cmd", "ps1", "js", "vbs", "hta", "iso", "img", "jar", "msi", "com", "pif");

    private static final Set<String> MACRO_ENABLED_EXTENSIONS = Set.of(
            "docm", "xlsm", "pptm", "dotm", "xltm");

    private static final Set<String> ARCHIVE_EXTENSIONS = Set.of("zip", "rar", "7z", "gz", "tar");

    public record AttachmentAnalysisResult(List<EmailAttachment> attachments, List<Finding> findings) {}

    public AttachmentAnalysisResult analyze(List<ParsedAttachment> parsedAttachments) {
        List<EmailAttachment> results = new ArrayList<>();
        List<Finding> findings = new ArrayList<>();

        if (parsedAttachments == null) return new AttachmentAnalysisResult(results, findings);

        for (ParsedAttachment pa : parsedAttachments) {
            EmailAttachment att = new EmailAttachment();
            att.setFilename(pa.filename());
            att.setDeclaredMimeType(pa.declaredMimeType());
            att.setSizeBytes(pa.sizeBytes());

            List<String> extensions = extractAllExtensions(pa.filename());
            String finalExt = extensions.isEmpty() ? "" : extensions.get(extensions.size() - 1);

            Severity risk = Severity.LOW;
            List<String> reasons = new ArrayList<>();

            boolean doubleExt = extensions.size() >= 2 && SUSPICIOUS_EXTENSIONS.contains(finalExt);
            att.setDoubleExtension(doubleExt);
            if (doubleExt) {
                reasons.add("Filename uses a double extension ending in an executable type, a common disguise technique.");
                risk = Severity.CRITICAL;
                findings.add(new Finding(FindingCategory.ATTACHMENT_ANALYSIS, Severity.CRITICAL,
                        "Double-extension executable attachment",
                        "The attachment filename disguises an executable behind what looks like a document extension (e.g. invoice.pdf.exe).",
                        "Filename: " + pa.filename(),
                        "Do not open this attachment. Report it to your security team and delete it.",
                        Severity.CRITICAL.getDefaultScoreImpact(), "T1566.001"));
            }

            boolean suspiciousExt = SUSPICIOUS_EXTENSIONS.contains(finalExt);
            att.setSuspiciousExtension(suspiciousExt);
            if (suspiciousExt && !doubleExt) {
                reasons.add("File extension (." + finalExt + ") is commonly used to deliver malware.");
                risk = maxSeverity(risk, Severity.HIGH);
                findings.add(new Finding(FindingCategory.ATTACHMENT_ANALYSIS, Severity.HIGH,
                        "Suspicious executable attachment type",
                        "The attachment has a file extension frequently used to deliver malware (." + finalExt + ").",
                        "Filename: " + pa.filename(),
                        "Do not open. Executable attachments should never be run from an email, regardless of the sender.",
                        Severity.HIGH.getDefaultScoreImpact(), "T1566.001"));
            }

            boolean macroEnabled = MACRO_ENABLED_EXTENSIONS.contains(finalExt);
            att.setMacroEnabled(macroEnabled);
            if (macroEnabled) {
                reasons.add("File is a macro-enabled Office document, which can execute code when opened.");
                risk = maxSeverity(risk, Severity.HIGH);
                findings.add(new Finding(FindingCategory.ATTACHMENT_ANALYSIS, Severity.HIGH,
                        "Macro-enabled Office attachment",
                        "Macro-enabled Office files (." + finalExt + ") can run embedded code (VBA macros) when the user enables content.",
                        "Filename: " + pa.filename(),
                        "Do not enable macros or 'editing' if this file must be opened. Prefer opening in a sandboxed/isolated viewer.",
                        Severity.HIGH.getDefaultScoreImpact(), "T1566.001"));
            }

            if (ARCHIVE_EXTENSIONS.contains(finalExt)) {
                reasons.add("Archive file — contents cannot be inspected without extraction; may hide an executable payload.");
                risk = maxSeverity(risk, Severity.MEDIUM);
                findings.add(new Finding(FindingCategory.ATTACHMENT_ANALYSIS, Severity.MEDIUM,
                        "Archive attachment",
                        "Archive files can conceal executable payloads from basic filtering and require extraction to inspect.",
                        "Filename: " + pa.filename(),
                        "Only extract in an isolated/sandboxed environment, never on a production endpoint.",
                        Severity.MEDIUM.getDefaultScoreImpact(), null));
            }

            if (pa.declaredMimeType() != null && pa.declaredMimeType().toLowerCase().contains("executable")) {
                reasons.add("Declared MIME type indicates an executable payload.");
                risk = maxSeverity(risk, Severity.HIGH);
            }

            att.setRisk(risk);
            att.setReason(reasons.isEmpty() ? "No significant risk indicators detected." : String.join(" ", reasons));
            results.add(att);
        }

        return new AttachmentAnalysisResult(results, findings);
    }

    private List<String> extractAllExtensions(String filename) {
        if (filename == null) return List.of();
        String[] parts = filename.toLowerCase().split("\\.");
        if (parts.length <= 1) return List.of();
        List<String> exts = new ArrayList<>();
        for (int i = 1; i < parts.length; i++) exts.add(parts[i]);
        return exts;
    }

    private Severity maxSeverity(Severity a, Severity b) {
        return a.ordinal() >= b.ordinal() ? a : b;
    }
}

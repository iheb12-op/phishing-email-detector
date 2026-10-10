package com.socanalyzer.phishingdetector.analyzer;

import com.socanalyzer.phishingdetector.model.Severity;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class AttachmentAnalyzerTest {

    private final AttachmentAnalyzer analyzer = new AttachmentAnalyzer();

    @Test
    void detectsDoubleExtensionExecutable() {
        var result = analyzer.analyze(List.of(new ParsedAttachment("invoice.pdf.exe", "application/octet-stream", 1000)));
        assertEquals(Severity.CRITICAL, result.attachments().get(0).getRisk());
        assertTrue(result.attachments().get(0).isDoubleExtension());
    }

    @Test
    void detectsSuspiciousSingleExtension() {
        var result = analyzer.analyze(List.of(new ParsedAttachment("payload.js", "text/javascript", 500)));
        assertTrue(result.attachments().get(0).isSuspiciousExtension());
    }

    @Test
    void doesNotFlagOrdinaryPdf() {
        var result = analyzer.analyze(List.of(new ParsedAttachment("statement.pdf", "application/pdf", 20000)));
        assertEquals(Severity.LOW, result.attachments().get(0).getRisk());
        assertFalse(result.attachments().get(0).isSuspiciousExtension());
    }

    @Test
    void detectsMacroEnabledOfficeDoc() {
        var result = analyzer.analyze(List.of(new ParsedAttachment("report.docm", "application/vnd.ms-word.document.macroEnabled.12", 5000)));
        assertTrue(result.attachments().get(0).isMacroEnabled());
    }
}

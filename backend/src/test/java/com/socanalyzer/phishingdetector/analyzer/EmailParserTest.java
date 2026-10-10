package com.socanalyzer.phishingdetector.analyzer;

import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

class EmailParserTest {

    private final EmailParser parser = new EmailParser();

    @Test
    void parsesPastedPlainTextEmail() {
        String raw = "From: Alice <alice@example.com>\nTo: bob@example.com\nSubject: Hello\n\nHi Bob, how are you?";
        ParsedEmail parsed = parser.parseRawText(raw);
        assertEquals("alice@example.com", parsed.fromAddress());
        assertEquals("Alice", parsed.fromDisplayName());
        assertEquals("Hello", parsed.subject());
    }

    @Test
    void rejectsOversizedInput() {
        String huge = "From: a@b.com\n\n".repeat(1_000_000);
        assertThrows(IllegalArgumentException.class, () -> parser.parseRawText(huge));
    }

    @Test
    void malformedEmailFallsBackGracefullyWithoutThrowing() {
        String malformed = "This is not really a valid email header block at all just some text";
        ParsedEmail parsed = parser.parseRawText(malformed);
        assertNotNull(parsed); // must not throw — malformed input is still handled (requirement #18 test case 12)
    }

    @Test
    void parsesEmlWithAttachment() throws Exception {
        byte[] eml = ("From: a@b.com\nTo: c@d.com\nSubject: test\nContent-Type: multipart/mixed; boundary=X\n\n" +
                "--X\nContent-Type: text/plain\n\nbody\n--X\n" +
                "Content-Type: application/octet-stream; name=\"invoice.pdf.exe\"\n" +
                "Content-Disposition: attachment; filename=\"invoice.pdf.exe\"\n\ndata\n--X--")
                .getBytes(StandardCharsets.UTF_8);
        ParsedEmail parsed = parser.parseEml(eml);
        assertEquals(1, parsed.attachments().size());
        assertEquals("invoice.pdf.exe", parsed.attachments().get(0).filename());
    }
}

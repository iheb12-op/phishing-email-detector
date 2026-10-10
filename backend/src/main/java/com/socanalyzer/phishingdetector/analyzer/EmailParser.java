package com.socanalyzer.phishingdetector.analyzer;

import jakarta.mail.BodyPart;
import jakarta.mail.Multipart;
import jakarta.mail.Part;
import jakarta.mail.Session;
import jakarta.mail.internet.MimeMessage;
import org.springframework.stereotype.Component;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.*;

/**
 * Parses either a raw .eml file (full MIME structure via Jakarta Mail) or
 * pasted plain email text (headers + body, regex-based fallback) into the
 * same normalized ParsedEmail model.
 *
 * SECURITY: this class treats all input as untrusted.
 *  - It never executes attachment content.
 *  - It never renders/executes HTML or embedded scripts — it only reads bytes.
 *  - It enforces a hard size ceiling before doing any parsing (defense against
 *    memory-exhaustion / decompression-bomb style abuse, requirement #17/#18
 *    "very large email" test case).
 */
@Component
public class EmailParser {

    private static final int MAX_RAW_SIZE_BYTES = 10 * 1024 * 1024; // matches multipart.max-file-size

    /** Parses a full .eml file (MIME multipart, attachments, real headers). */
    public ParsedEmail parseEml(byte[] emlBytes) throws IOException {
        if (emlBytes.length > MAX_RAW_SIZE_BYTES) {
            throw new IllegalArgumentException("Email exceeds maximum allowed size of " + MAX_RAW_SIZE_BYTES + " bytes");
        }
        try {
            Session session = Session.getDefaultInstance(new Properties());
            MimeMessage message = new MimeMessage(session, new ByteArrayInputStream(emlBytes));

            Map<String, String> allHeaders = new LinkedHashMap<>();
            Enumeration<?> headerLines = message.getAllHeaders();
            while (headerLines.hasMoreElements()) {
                jakarta.mail.Header h = (jakarta.mail.Header) headerLines.nextElement();
                allHeaders.merge(h.getName(), h.getValue(), (a, b) -> a + "; " + b);
            }

            String fromRaw = firstOrNull(message.getHeader("From"));
            String[] fromParsed = splitDisplayNameAndAddress(fromRaw);

            List<String> receivedChain = new ArrayList<>();
            String[] received = message.getHeader("Received");
            if (received != null) receivedChain.addAll(Arrays.asList(received));

            StringBuilder textBody = new StringBuilder();
            StringBuilder htmlBody = new StringBuilder();
            List<ParsedAttachment> attachments = new ArrayList<>();
            List<ParsedLink> ignored = new ArrayList<>(); // links extracted separately by UrlAnalyzer from bodies

            extractParts(message, textBody, htmlBody, attachments);

            return new ParsedEmail(
                    fromRaw,
                    fromParsed[1],
                    fromParsed[0],
                    firstOrNull(message.getHeader("To")),
                    firstOrNull(message.getHeader("Reply-To")),
                    firstOrNull(message.getHeader("Return-Path")),
                    message.getSubject(),
                    firstOrNull(message.getHeader("Message-ID")),
                    firstOrNull(message.getHeader("Date")),
                    receivedChain,
                    firstOrNull(message.getHeader("Authentication-Results")),
                    textBody.toString(),
                    htmlBody.toString(),
                    attachments,
                    allHeaders
            );
        } catch (jakarta.mail.MessagingException e) {
            throw new IOException("Malformed email: unable to parse MIME structure", e);
        }
    }

    /** Fallback parser for pasted plain text that may or may not have proper MIME structure. */
    public ParsedEmail parseRawText(String raw) {
        if (raw.getBytes(StandardCharsets.UTF_8).length > MAX_RAW_SIZE_BYTES) {
            throw new IllegalArgumentException("Email exceeds maximum allowed size of " + MAX_RAW_SIZE_BYTES + " bytes");
        }
        // Try full MIME parsing first (pasted text is often a full raw email export)
        try {
            return parseEml(raw.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            // Fall through to lightweight regex parsing for loosely-formatted pasted content
        }

        Map<String, String> headers = new LinkedHashMap<>();
        String body = raw;
        int blankLineIdx = raw.indexOf("\n\n");
        String headerBlock = blankLineIdx > 0 ? raw.substring(0, blankLineIdx) : raw;
        if (blankLineIdx > 0) body = raw.substring(blankLineIdx + 2);

        String currentKey = null;
        StringBuilder currentVal = new StringBuilder();
        for (String line : headerBlock.split("\n")) {
            if (line.matches("^[A-Za-z-]+:.*") ) {
                if (currentKey != null) headers.put(currentKey, currentVal.toString().trim());
                int colon = line.indexOf(':');
                currentKey = line.substring(0, colon).trim();
                currentVal = new StringBuilder(line.substring(colon + 1));
            } else if (currentKey != null && (line.startsWith(" ") || line.startsWith("\t"))) {
                currentVal.append(" ").append(line.trim()); // folded header continuation
            }
        }
        if (currentKey != null) headers.put(currentKey, currentVal.toString().trim());

        String fromRaw = headers.get("From");
        String[] fromParsed = splitDisplayNameAndAddress(fromRaw);

        List<String> receivedChain = new ArrayList<>();
        headers.forEach((k, v) -> { if (k.equalsIgnoreCase("Received")) receivedChain.add(v); });

        boolean looksHtml = body.trim().toLowerCase().startsWith("<") || body.toLowerCase().contains("<html");

        return new ParsedEmail(
                fromRaw,
                fromParsed[1],
                fromParsed[0],
                headers.get("To"),
                headers.get("Reply-To"),
                headers.get("Return-Path"),
                headers.get("Subject"),
                headers.get("Message-ID"),
                headers.get("Date"),
                receivedChain,
                headers.get("Authentication-Results"),
                looksHtml ? "" : body,
                looksHtml ? body : "",
                new ArrayList<>(),
                headers
        );
    }

    private void extractParts(Part part, StringBuilder textBody, StringBuilder htmlBody,
                               List<ParsedAttachment> attachments) throws jakarta.mail.MessagingException, IOException {
        if (part.isMimeType("text/plain") && !Part.ATTACHMENT.equalsIgnoreCase(part.getDisposition())) {
            textBody.append(part.getContent().toString()).append("\n");
        } else if (part.isMimeType("text/html") && !Part.ATTACHMENT.equalsIgnoreCase(part.getDisposition())) {
            htmlBody.append(part.getContent().toString()).append("\n");
        } else if (part.isMimeType("multipart/*")) {
            Multipart mp = (Multipart) part.getContent();
            for (int i = 0; i < mp.getCount(); i++) {
                extractParts(mp.getBodyPart(i), textBody, htmlBody, attachments);
            }
        } else if (Part.ATTACHMENT.equalsIgnoreCase(part.getDisposition()) || part.getFileName() != null) {
            // Metadata only — content bytes are deliberately not stored (requirement #17/#8)
            long size = part.getSize() > 0 ? part.getSize() : 0;
            attachments.add(new ParsedAttachment(part.getFileName(), part.getContentType(), size));
        }
    }

    private String firstOrNull(String[] values) {
        return values != null && values.length > 0 ? values[0] : null;
    }

    /** Splits "Display Name <addr@example.com>" into {displayName, address}. */
    private String[] splitDisplayNameAndAddress(String fromRaw) {
        if (fromRaw == null) return new String[]{null, null};
        int lt = fromRaw.indexOf('<');
        int gt = fromRaw.indexOf('>');
        if (lt >= 0 && gt > lt) {
            String display = fromRaw.substring(0, lt).trim().replaceAll("^\"|\"$", "");
            String addr = fromRaw.substring(lt + 1, gt).trim();
            return new String[]{display.isEmpty() ? null : display, addr};
        }
        return new String[]{null, fromRaw.trim()};
    }
}

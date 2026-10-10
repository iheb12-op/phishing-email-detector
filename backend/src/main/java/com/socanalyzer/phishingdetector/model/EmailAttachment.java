package com.socanalyzer.phishingdetector.model;

import jakarta.persistence.*;
import java.util.UUID;

/** A file attachment declared in the email (metadata only — content is never executed). */
@Entity
@Table(name = "email_attachment")
public class EmailAttachment {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "analysis_id")
    private EmailAnalysis analysis;

    private String filename;
    private String declaredMimeType;
    private long sizeBytes;

    @Enumerated(EnumType.STRING)
    private Severity risk;

    @Column(length = 1000)
    private String reason;

    private boolean doubleExtension;
    private boolean suspiciousExtension;
    private boolean macroEnabled;

    public UUID getId() { return id; }
    public EmailAnalysis getAnalysis() { return analysis; }
    public void setAnalysis(EmailAnalysis analysis) { this.analysis = analysis; }
    public String getFilename() { return filename; }
    public void setFilename(String filename) { this.filename = filename; }
    public String getDeclaredMimeType() { return declaredMimeType; }
    public void setDeclaredMimeType(String declaredMimeType) { this.declaredMimeType = declaredMimeType; }
    public long getSizeBytes() { return sizeBytes; }
    public void setSizeBytes(long sizeBytes) { this.sizeBytes = sizeBytes; }
    public Severity getRisk() { return risk; }
    public void setRisk(Severity risk) { this.risk = risk; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
    public boolean isDoubleExtension() { return doubleExtension; }
    public void setDoubleExtension(boolean doubleExtension) { this.doubleExtension = doubleExtension; }
    public boolean isSuspiciousExtension() { return suspiciousExtension; }
    public void setSuspiciousExtension(boolean suspiciousExtension) { this.suspiciousExtension = suspiciousExtension; }
    public boolean isMacroEnabled() { return macroEnabled; }
    public void setMacroEnabled(boolean macroEnabled) { this.macroEnabled = macroEnabled; }
}

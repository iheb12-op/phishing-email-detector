package com.socanalyzer.phishingdetector.model;

import jakarta.persistence.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Root entity of an analysis run. One EmailAnalysis is created per submitted
 * email (pasted text or .eml upload) and owns its headers, findings, URLs,
 * attachments and MITRE ATT&CK mappings so a past investigation can be
 * fully reviewed later (requirement #16).
 */
@Entity
@Table(name = "email_analysis")
public class EmailAnalysis {

    @Id
    @GeneratedValue
    private UUID id;

    @Column(nullable = false)
    private Instant analyzedAt = Instant.now();

    private String fromAddress;
    private String fromDisplayName;
    private String toAddress;
    private String replyToAddress;
    private String subject;
    private String messageId;
    private String originDate; // raw Date header, kept as string (untrusted input)

    @Enumerated(EnumType.STRING)
    private AuthResult spfResult = AuthResult.UNKNOWN;

    @Enumerated(EnumType.STRING)
    private AuthResult dkimResult = AuthResult.UNKNOWN;

    @Enumerated(EnumType.STRING)
    private AuthResult dmarcResult = AuthResult.UNKNOWN;

    private int riskScore;

    @Enumerated(EnumType.STRING)
    private Verdict verdict = Verdict.SAFE;

    // Source type: PASTED_TEXT or EML_UPLOAD — useful for stats and audit trail
    private String sourceType;

    @OneToMany(mappedBy = "analysis", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<Finding> findings = new ArrayList<>();

    @OneToMany(mappedBy = "analysis", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ExtractedUrl> extractedUrls = new ArrayList<>();

    @OneToMany(mappedBy = "analysis", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<EmailAttachment> attachments = new ArrayList<>();

    @OneToMany(mappedBy = "analysis", cascade = CascadeType.ALL, orphanRemoval = true)
    private List<ThreatIndicator> threatIndicators = new ArrayList<>();

    // --- getters / setters ---
    public UUID getId() { return id; }
    public void setId(UUID id) { this.id = id; }
    public Instant getAnalyzedAt() { return analyzedAt; }
    public void setAnalyzedAt(Instant analyzedAt) { this.analyzedAt = analyzedAt; }
    public String getFromAddress() { return fromAddress; }
    public void setFromAddress(String fromAddress) { this.fromAddress = fromAddress; }
    public String getFromDisplayName() { return fromDisplayName; }
    public void setFromDisplayName(String fromDisplayName) { this.fromDisplayName = fromDisplayName; }
    public String getToAddress() { return toAddress; }
    public void setToAddress(String toAddress) { this.toAddress = toAddress; }
    public String getReplyToAddress() { return replyToAddress; }
    public void setReplyToAddress(String replyToAddress) { this.replyToAddress = replyToAddress; }
    public String getSubject() { return subject; }
    public void setSubject(String subject) { this.subject = subject; }
    public String getMessageId() { return messageId; }
    public void setMessageId(String messageId) { this.messageId = messageId; }
    public String getOriginDate() { return originDate; }
    public void setOriginDate(String originDate) { this.originDate = originDate; }
    public AuthResult getSpfResult() { return spfResult; }
    public void setSpfResult(AuthResult spfResult) { this.spfResult = spfResult; }
    public AuthResult getDkimResult() { return dkimResult; }
    public void setDkimResult(AuthResult dkimResult) { this.dkimResult = dkimResult; }
    public AuthResult getDmarcResult() { return dmarcResult; }
    public void setDmarcResult(AuthResult dmarcResult) { this.dmarcResult = dmarcResult; }
    public int getRiskScore() { return riskScore; }
    public void setRiskScore(int riskScore) { this.riskScore = riskScore; }
    public Verdict getVerdict() { return verdict; }
    public void setVerdict(Verdict verdict) { this.verdict = verdict; }
    public String getSourceType() { return sourceType; }
    public void setSourceType(String sourceType) { this.sourceType = sourceType; }
    public List<Finding> getFindings() { return findings; }
    public List<ExtractedUrl> getExtractedUrls() { return extractedUrls; }
    public List<EmailAttachment> getAttachments() { return attachments; }
    public List<ThreatIndicator> getThreatIndicators() { return threatIndicators; }

    public void addFinding(Finding f) { f.setAnalysis(this); this.findings.add(f); }
    public void addUrl(ExtractedUrl u) { u.setAnalysis(this); this.extractedUrls.add(u); }
    public void addAttachment(EmailAttachment a) { a.setAnalysis(this); this.attachments.add(a); }
    public void addThreatIndicator(ThreatIndicator t) { t.setAnalysis(this); this.threatIndicators.add(t); }
}

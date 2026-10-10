package com.socanalyzer.phishingdetector.model;

import jakarta.persistence.*;
import java.util.UUID;

/** A URL extracted from the email body (plain text or HTML href), with its computed risk. */
@Entity
@Table(name = "extracted_url")
public class ExtractedUrl {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "analysis_id")
    private EmailAnalysis analysis;

    @Column(length = 2048)
    private String url;

    private String domain;

    @Enumerated(EnumType.STRING)
    private Severity risk;

    @Column(length = 1000)
    private String reason;

    // For HTML links: what text was displayed vs where it actually points
    @Column(length = 500)
    private String displayedText;

    private boolean domainMismatch;
    private boolean usesIpAddress;
    private boolean isShortener;
    private boolean isPunycode;
    private boolean usesHttps;

    public UUID getId() { return id; }
    public EmailAnalysis getAnalysis() { return analysis; }
    public void setAnalysis(EmailAnalysis analysis) { this.analysis = analysis; }
    public String getUrl() { return url; }
    public void setUrl(String url) { this.url = url; }
    public String getDomain() { return domain; }
    public void setDomain(String domain) { this.domain = domain; }
    public Severity getRisk() { return risk; }
    public void setRisk(Severity risk) { this.risk = risk; }
    public String getReason() { return reason; }
    public void setReason(String reason) { this.reason = reason; }
    public String getDisplayedText() { return displayedText; }
    public void setDisplayedText(String displayedText) { this.displayedText = displayedText; }
    public boolean isDomainMismatch() { return domainMismatch; }
    public void setDomainMismatch(boolean domainMismatch) { this.domainMismatch = domainMismatch; }
    public boolean isUsesIpAddress() { return usesIpAddress; }
    public void setUsesIpAddress(boolean usesIpAddress) { this.usesIpAddress = usesIpAddress; }
    public boolean isShortener() { return isShortener; }
    public void setShortener(boolean shortener) { isShortener = shortener; }
    public boolean isPunycode() { return isPunycode; }
    public void setPunycode(boolean punycode) { isPunycode = punycode; }
    public boolean isUsesHttps() { return usesHttps; }
    public void setUsesHttps(boolean usesHttps) { this.usesHttps = usesHttps; }
}

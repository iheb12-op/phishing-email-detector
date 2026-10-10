package com.socanalyzer.phishingdetector.model;

import jakarta.persistence.*;
import java.util.UUID;

/** Raw header name/value pairs kept for audit trail and manual SOC review. */
@Entity
@Table(name = "email_header")
public class EmailHeader {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "analysis_id")
    private EmailAnalysis analysis;

    private String name;

    @Column(name = "header_value", length = 4000)
    private String value;

    public UUID getId() { return id; }
    public EmailAnalysis getAnalysis() { return analysis; }
    public void setAnalysis(EmailAnalysis analysis) { this.analysis = analysis; }
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    public String getValue() { return value; }
    public void setValue(String value) { this.value = value; }
}

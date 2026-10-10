package com.socanalyzer.phishingdetector.model;

import jakarta.persistence.*;
import java.util.UUID;

/** A MITRE ATT&CK technique mapping derived from one or more findings (requirement #12). */
@Entity
@Table(name = "threat_indicator")
public class ThreatIndicator {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "analysis_id")
    private EmailAnalysis analysis;

    private String techniqueId;   // e.g. T1566.002
    private String techniqueName; // e.g. "Phishing: Spearphishing Link"

    @Column(length = 1000)
    private String justification;

    public UUID getId() { return id; }
    public EmailAnalysis getAnalysis() { return analysis; }
    public void setAnalysis(EmailAnalysis analysis) { this.analysis = analysis; }
    public String getTechniqueId() { return techniqueId; }
    public void setTechniqueId(String techniqueId) { this.techniqueId = techniqueId; }
    public String getTechniqueName() { return techniqueName; }
    public void setTechniqueName(String techniqueName) { this.techniqueName = techniqueName; }
    public String getJustification() { return justification; }
    public void setJustification(String justification) { this.justification = justification; }
}

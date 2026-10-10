package com.socanalyzer.phishingdetector.model;

import jakarta.persistence.*;
import java.util.UUID;

/**
 * A single, explainable security finding produced by an analyzer.
 * This is the core "explainability" object required by requirement #11 —
 * the app must never just say "Phishing", it must say why.
 */
@Entity
@Table(name = "finding")
public class Finding {

    @Id
    @GeneratedValue
    private UUID id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "analysis_id")
    private EmailAnalysis analysis;

    @Enumerated(EnumType.STRING)
    private FindingCategory category;

    @Enumerated(EnumType.STRING)
    private Severity severity;

    private String title;

    @Column(length = 2000)
    private String description;

    @Column(length = 2000)
    private String evidence;

    @Column(length = 1000)
    private String recommendation;

    private int scoreImpact;

    // Optional MITRE technique this finding maps to, e.g. "T1566.002"
    private String mitreTechniqueId;

    public Finding() {}

    public Finding(FindingCategory category, Severity severity, String title, String description,
                    String evidence, String recommendation, int scoreImpact, String mitreTechniqueId) {
        this.category = category;
        this.severity = severity;
        this.title = title;
        this.description = description;
        this.evidence = evidence;
        this.recommendation = recommendation;
        this.scoreImpact = scoreImpact;
        this.mitreTechniqueId = mitreTechniqueId;
    }

    public UUID getId() { return id; }
    public EmailAnalysis getAnalysis() { return analysis; }
    public void setAnalysis(EmailAnalysis analysis) { this.analysis = analysis; }
    public FindingCategory getCategory() { return category; }
    public void setCategory(FindingCategory category) { this.category = category; }
    public Severity getSeverity() { return severity; }
    public void setSeverity(Severity severity) { this.severity = severity; }
    public String getTitle() { return title; }
    public void setTitle(String title) { this.title = title; }
    public String getDescription() { return description; }
    public void setDescription(String description) { this.description = description; }
    public String getEvidence() { return evidence; }
    public void setEvidence(String evidence) { this.evidence = evidence; }
    public String getRecommendation() { return recommendation; }
    public void setRecommendation(String recommendation) { this.recommendation = recommendation; }
    public int getScoreImpact() { return scoreImpact; }
    public void setScoreImpact(int scoreImpact) { this.scoreImpact = scoreImpact; }
    public String getMitreTechniqueId() { return mitreTechniqueId; }
    public void setMitreTechniqueId(String mitreTechniqueId) { this.mitreTechniqueId = mitreTechniqueId; }
}

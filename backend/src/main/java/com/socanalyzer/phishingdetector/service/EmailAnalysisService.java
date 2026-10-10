package com.socanalyzer.phishingdetector.service;

import com.socanalyzer.phishingdetector.analyzer.*;
import com.socanalyzer.phishingdetector.dto.*;
import com.socanalyzer.phishingdetector.model.*;
import com.socanalyzer.phishingdetector.repository.EmailAnalysisRepository;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.IOException;
import java.util.*;

/**
 * Orchestrates the full analysis pipeline:
 *   ParsedEmail -> [Sender, Header, Url, Domain(via others), Attachment,
 *                   Content, Html] analyzers -> RiskScoringEngine ->
 *                   MitreAttackMapper -> persisted EmailAnalysis.
 *
 * This is the single place that decides the order analyzers run in and
 * aggregates every Finding produced, keeping each analyzer independently
 * testable and free of orchestration concerns.
 */
@Service
public class EmailAnalysisService {

    private final EmailParser emailParser;
    private final HeaderAnalyzer headerAnalyzer;
    private final SenderAnalyzer senderAnalyzer;
    private final UrlAnalyzer urlAnalyzer;
    private final AttachmentAnalyzer attachmentAnalyzer;
    private final ContentKeywordAnalyzer contentKeywordAnalyzer;
    private final HtmlAnalyzer htmlAnalyzer;
    private final RiskScoringEngine riskScoringEngine;
    private final MitreAttackMapper mitreAttackMapper;
    private final EmailAnalysisRepository repository;

    public EmailAnalysisService(EmailParser emailParser, HeaderAnalyzer headerAnalyzer, SenderAnalyzer senderAnalyzer,
                                 UrlAnalyzer urlAnalyzer, AttachmentAnalyzer attachmentAnalyzer,
                                 ContentKeywordAnalyzer contentKeywordAnalyzer, HtmlAnalyzer htmlAnalyzer,
                                 RiskScoringEngine riskScoringEngine, MitreAttackMapper mitreAttackMapper,
                                 EmailAnalysisRepository repository) {
        this.emailParser = emailParser;
        this.headerAnalyzer = headerAnalyzer;
        this.senderAnalyzer = senderAnalyzer;
        this.urlAnalyzer = urlAnalyzer;
        this.attachmentAnalyzer = attachmentAnalyzer;
        this.contentKeywordAnalyzer = contentKeywordAnalyzer;
        this.htmlAnalyzer = htmlAnalyzer;
        this.riskScoringEngine = riskScoringEngine;
        this.mitreAttackMapper = mitreAttackMapper;
        this.repository = repository;
    }

    @Transactional
    public AnalysisResponse analyzeRawText(String rawEmail) {
        ParsedEmail parsed = emailParser.parseRawText(rawEmail);
        return runPipeline(parsed, "PASTED_TEXT");
    }

    @Transactional
    public AnalysisResponse analyzeEml(byte[] emlBytes) throws IOException {
        ParsedEmail parsed = emailParser.parseEml(emlBytes);
        return runPipeline(parsed, "EML_UPLOAD");
    }

    private AnalysisResponse runPipeline(ParsedEmail parsed, String sourceType) {
        List<Finding> allFindings = new ArrayList<>();

        HeaderAnalyzer.HeaderAnalysisResult headerResult = headerAnalyzer.analyze(parsed);
        allFindings.addAll(headerResult.findings());

        allFindings.addAll(senderAnalyzer.analyze(parsed));

        UrlAnalyzer.UrlAnalysisResult urlResult = urlAnalyzer.analyze(parsed);
        allFindings.addAll(urlResult.findings());

        AttachmentAnalyzer.AttachmentAnalysisResult attachmentResult = attachmentAnalyzer.analyze(parsed.attachments());
        allFindings.addAll(attachmentResult.findings());

        allFindings.addAll(contentKeywordAnalyzer.analyze(parsed.subject(), parsed.textBody(), parsed.htmlBody()));
        allFindings.addAll(htmlAnalyzer.analyze(parsed.htmlBody()));

        RiskScoringEngine.ScoringResult scoring = riskScoringEngine.score(allFindings);
        List<ThreatIndicator> mitreIndicators = mitreAttackMapper.mapFindings(allFindings);

        EmailAnalysis analysis = new EmailAnalysis();
        analysis.setFromAddress(parsed.fromAddress());
        analysis.setFromDisplayName(parsed.fromDisplayName());
        analysis.setToAddress(parsed.toAddress());
        analysis.setReplyToAddress(parsed.replyToAddress());
        analysis.setSubject(parsed.subject());
        analysis.setMessageId(parsed.messageId());
        analysis.setOriginDate(parsed.dateHeader());
        analysis.setSpfResult(headerResult.spf());
        analysis.setDkimResult(headerResult.dkim());
        analysis.setDmarcResult(headerResult.dmarc());
        analysis.setRiskScore(scoring.totalScore());
        analysis.setVerdict(scoring.verdict());
        analysis.setSourceType(sourceType);

        allFindings.forEach(analysis::addFinding);
        urlResult.urls().forEach(analysis::addUrl);
        attachmentResult.attachments().forEach(analysis::addAttachment);
        mitreIndicators.forEach(analysis::addThreatIndicator);

        EmailAnalysis saved = repository.save(analysis);
        return toResponse(saved);
    }

    @Transactional(readOnly = true)
    public Optional<AnalysisResponse> getAnalysis(UUID id) {
        return repository.findById(id).map(this::toResponse);
    }

    @Transactional(readOnly = true)
    public AnalysisStatsResponse getStats() {
        long total = repository.count();
        Map<String, Long> breakdown = new LinkedHashMap<>();
        for (Verdict v : Verdict.values()) {
            breakdown.put(v.name(), repository.countByVerdict(v));
        }
        Double avg = repository.averageRiskScore();
        return new AnalysisStatsResponse(total, breakdown, avg != null ? avg : 0.0);
    }

    private AnalysisResponse toResponse(EmailAnalysis a) {
        List<FindingDto> findings = a.getFindings().stream().map(f -> new FindingDto(
                f.getId().toString(), f.getCategory().name(), f.getSeverity().name(), f.getTitle(),
                f.getDescription(), f.getEvidence(), f.getRecommendation(), f.getScoreImpact(), f.getMitreTechniqueId()
        )).toList();

        List<ExtractedUrlDto> urls = a.getExtractedUrls().stream().map(u -> new ExtractedUrlDto(
                u.getId().toString(), u.getUrl(), u.getDomain(), u.getRisk() != null ? u.getRisk().name() : "LOW",
                u.getReason(), u.getDisplayedText(), u.isDomainMismatch(), u.isUsesIpAddress(), u.isShortener(),
                u.isPunycode(), u.isUsesHttps()
        )).toList();

        List<AttachmentDto> attachments = a.getAttachments().stream().map(att -> new AttachmentDto(
                att.getId().toString(), att.getFilename(), att.getDeclaredMimeType(), att.getSizeBytes(),
                att.getRisk() != null ? att.getRisk().name() : "LOW", att.getReason(), att.isDoubleExtension(),
                att.isSuspiciousExtension(), att.isMacroEnabled()
        )).toList();

        List<MitreMappingDto> mitre = a.getThreatIndicators().stream().map(t -> new MitreMappingDto(
                t.getTechniqueId(), t.getTechniqueName(), t.getJustification()
        )).toList();

        return new AnalysisResponse(
                a.getId().toString(),
                a.getAnalyzedAt(),
                a.getRiskScore(),
                a.getVerdict().name(),
                new EmailOverviewDto(a.getFromAddress(), a.getFromDisplayName(), a.getToAddress(),
                        a.getReplyToAddress(), a.getSubject(), a.getMessageId(), a.getOriginDate()),
                new AuthenticationSummaryDto(a.getSpfResult().name(), a.getDkimResult().name(), a.getDmarcResult().name()),
                findings,
                urls,
                attachments,
                mitre,
                buildRecommendedActions(a)
        );
    }

    private List<String> buildRecommendedActions(EmailAnalysis a) {
        List<String> actions = new ArrayList<>();
        switch (a.getVerdict()) {
            case HIGH_CONFIDENCE_PHISHING, LIKELY_PHISHING -> {
                actions.add("Do not click any links or open any attachments in this email.");
                actions.add("Report this email to your security team / SOC immediately.");
                actions.add("If any credentials were entered on a linked site, change them immediately and enable MFA.");
                actions.add("Delete the email after reporting, or quarantine it per your organization's policy.");
            }
            case SUSPICIOUS -> {
                actions.add("Verify the sender through an independent, known-good communication channel before acting.");
                actions.add("Do not click links or open attachments until the sender is verified.");
                actions.add("Consider reporting to your security team for a second opinion.");
            }
            case SAFE -> actions.add("No significant phishing indicators were found, but always remain cautious with unexpected requests.");
        }
        return actions;
    }
}

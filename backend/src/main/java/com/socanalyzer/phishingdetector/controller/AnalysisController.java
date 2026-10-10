package com.socanalyzer.phishingdetector.controller;

import com.socanalyzer.phishingdetector.dto.*;
import com.socanalyzer.phishingdetector.service.EmailAnalysisService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.List;
import java.util.UUID;

/**
 * REST API for the Phishing Email Detector (requirement #15).
 * Every endpoint operates on untrusted input — see EmailParser/AttachmentAnalyzer
 * for the corresponding safe-handling measures.
 */
@RestController
@RequestMapping("/api")
public class AnalysisController {

    private static final long MAX_EML_SIZE = 10 * 1024 * 1024; // 10MB, matches application.yml

    private final EmailAnalysisService service;

    public AnalysisController(EmailAnalysisService service) {
        this.service = service;
    }

    @PostMapping("/analyze/email")
    public ResponseEntity<AnalysisResponse> analyzeEmail(@Valid @RequestBody AnalyzeEmailRequest request) {
        return ResponseEntity.ok(service.analyzeRawText(request.getRawEmail()));
    }

    @PostMapping(value = "/analyze/eml", consumes = "multipart/form-data")
    public ResponseEntity<?> analyzeEml(@RequestParam("file") MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body(java.util.Map.of("error", "Uploaded file is empty"));
        }
        if (file.getSize() > MAX_EML_SIZE) {
            return ResponseEntity.badRequest().body(java.util.Map.of("error", "File exceeds maximum allowed size (10MB)"));
        }
        String filename = file.getOriginalFilename();
        // Basic extension allow-listing + path traversal protection (requirement #17)
        if (filename == null || filename.contains("..") || !filename.toLowerCase().endsWith(".eml")) {
            return ResponseEntity.badRequest().body(java.util.Map.of("error", "Only .eml files are accepted"));
        }
        return ResponseEntity.ok(service.analyzeEml(file.getBytes()));
    }

    @GetMapping("/analysis/{id}")
    public ResponseEntity<AnalysisResponse> getAnalysis(@PathVariable UUID id) {
        return service.getAnalysis(id)
                .map(ResponseEntity::ok)
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    @GetMapping("/analysis/{id}/findings")
    public ResponseEntity<List<FindingDto>> getFindings(@PathVariable UUID id) {
        return service.getAnalysis(id)
                .map(a -> ResponseEntity.ok(a.findings()))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    @GetMapping("/analysis/{id}/urls")
    public ResponseEntity<List<ExtractedUrlDto>> getUrls(@PathVariable UUID id) {
        return service.getAnalysis(id)
                .map(a -> ResponseEntity.ok(a.urls()))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    @GetMapping("/analysis/{id}/attachments")
    public ResponseEntity<List<AttachmentDto>> getAttachments(@PathVariable UUID id) {
        return service.getAnalysis(id)
                .map(a -> ResponseEntity.ok(a.attachments()))
                .orElseGet(() -> ResponseEntity.status(HttpStatus.NOT_FOUND).build());
    }

    @GetMapping("/stats")
    public ResponseEntity<AnalysisStatsResponse> getStats() {
        return ResponseEntity.ok(service.getStats());
    }
}

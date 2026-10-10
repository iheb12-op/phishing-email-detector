package com.socanalyzer.phishingdetector.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.time.Instant;
import java.util.Map;

/**
 * GET /api/health
 *
 * Simple liveness endpoint. Used by Docker healthchecks and to verify
 * the backend is reachable from the frontend before wiring up real
 * analysis endpoints in later phases.
 */
@RestController
@RequestMapping("/api")
public class HealthController {

    @GetMapping("/health")
    public Map<String, Object> health() {
        return Map.of(
                "status", "UP",
                "service", "phishing-detector-backend",
                "timestamp", Instant.now().toString()
        );
    }
}

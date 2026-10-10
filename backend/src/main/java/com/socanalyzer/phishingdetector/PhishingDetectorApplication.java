package com.socanalyzer.phishingdetector;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

/**
 * Entry point for the Phishing Email Detector backend.
 *
 * This is an educational, DEFENSIVE security tool. It analyzes emails
 * (pasted text or uploaded .eml files) for phishing indicators. It never
 * executes attachments, never runs JavaScript found in HTML emails, and
 * never automatically fetches remote URLs found in analyzed content.
 */
@SpringBootApplication
public class PhishingDetectorApplication {
    public static void main(String[] args) {
        SpringApplication.run(PhishingDetectorApplication.class, args);
    }
}

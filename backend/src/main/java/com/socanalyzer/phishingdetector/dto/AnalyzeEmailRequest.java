package com.socanalyzer.phishingdetector.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;

/** Request body for POST /api/analyze/email (pasted raw email text). */
public class AnalyzeEmailRequest {

    @NotBlank(message = "rawEmail must not be blank")
    @Size(max = 500_000, message = "rawEmail exceeds maximum allowed size")
    private String rawEmail;

    public String getRawEmail() { return rawEmail; }
    public void setRawEmail(String rawEmail) { this.rawEmail = rawEmail; }
}

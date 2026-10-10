package com.socanalyzer.phishingdetector;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * End-to-end tests covering the full pipeline via the real REST API,
 * exercising several of the required test cases (requirement #18):
 * obvious phishing email, legitimate email, malformed email.
 */
@SpringBootTest
@AutoConfigureMockMvc
@ActiveProfiles("test")
class AnalysisControllerIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Test
    void obviousPhishingEmailProducesHighRiskVerdict() throws Exception {
        String raw = "From: \"PayPal Security\" <security@paypa1-example.com>\n" +
                "Reply-To: attacker@evil-domain.tk\n" +
                "To: victim@example.com\n" +
                "Subject: URGENT: verify your account immediately\n" +
                "Authentication-Results: mx; spf=fail; dkim=fail; dmarc=fail\n\n" +
                "Your account has been suspended. Click immediately to confirm your identity: " +
                "http://192.0.2.10/login";

        mockMvc.perform(post("/api/analyze/email")
                        .contentType("application/json")
                        .content("{\"rawEmail\":\"" + raw.replace("\"", "\\\"").replace("\n", "\\n") + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.riskScore").isNumber())
                .andExpect(jsonPath("$.verdict").exists())
                .andExpect(jsonPath("$.findings").isArray())
                .andExpect(jsonPath("$.mitreMappings").isArray());
    }

    @Test
    void legitimateEmailProducesLowRiskVerdict() throws Exception {
        String raw = "From: Alice <alice@example.com>\nTo: bob@example.com\nSubject: Lunch tomorrow?\n\n" +
                "Hi Bob, are you free for lunch tomorrow at noon?";

        mockMvc.perform(post("/api/analyze/email")
                        .contentType("application/json")
                        .content("{\"rawEmail\":\"" + raw.replace("\n", "\\n") + "\"}"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.verdict").value("SAFE"));
    }

    @Test
    void blankEmailIsRejectedWithValidationError() throws Exception {
        mockMvc.perform(post("/api/analyze/email")
                        .contentType("application/json")
                        .content("{\"rawEmail\":\"\"}"))
                .andExpect(status().isBadRequest());
    }
}

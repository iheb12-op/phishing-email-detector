package com.socanalyzer.phishingdetector.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

/**
 * Configurable score-impact weights per severity level (requirement #10).
 * Bound from scoring-weights.yml so weights can be tuned without a code
 * change or redeploy of analyzer logic — important in a real SOC where
 * detection tuning is a continuous, low-friction process.
 */
@Component
@ConfigurationProperties(prefix = "scoring")
public class ScoringWeightsProperties {

    private int lowWeight = 5;
    private int mediumWeight = 15;
    private int highWeight = 30;
    private int criticalWeight = 50;

    private int safeThreshold = 25;         // below this: SAFE
    private int suspiciousThreshold = 50;   // below this: SUSPICIOUS
    private int likelyPhishingThreshold = 75; // below this: LIKELY_PHISHING, else HIGH_CONFIDENCE_PHISHING

    private int maxScore = 100;

    public int getLowWeight() { return lowWeight; }
    public void setLowWeight(int lowWeight) { this.lowWeight = lowWeight; }
    public int getMediumWeight() { return mediumWeight; }
    public void setMediumWeight(int mediumWeight) { this.mediumWeight = mediumWeight; }
    public int getHighWeight() { return highWeight; }
    public void setHighWeight(int highWeight) { this.highWeight = highWeight; }
    public int getCriticalWeight() { return criticalWeight; }
    public void setCriticalWeight(int criticalWeight) { this.criticalWeight = criticalWeight; }
    public int getSafeThreshold() { return safeThreshold; }
    public void setSafeThreshold(int safeThreshold) { this.safeThreshold = safeThreshold; }
    public int getSuspiciousThreshold() { return suspiciousThreshold; }
    public void setSuspiciousThreshold(int suspiciousThreshold) { this.suspiciousThreshold = suspiciousThreshold; }
    public int getLikelyPhishingThreshold() { return likelyPhishingThreshold; }
    public void setLikelyPhishingThreshold(int likelyPhishingThreshold) { this.likelyPhishingThreshold = likelyPhishingThreshold; }
    public int getMaxScore() { return maxScore; }
    public void setMaxScore(int maxScore) { this.maxScore = maxScore; }
}

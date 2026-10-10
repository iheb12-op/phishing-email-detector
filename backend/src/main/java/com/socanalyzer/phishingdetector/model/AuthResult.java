package com.socanalyzer.phishingdetector.model;

/** Result of an SPF/DKIM/DMARC check as parsed from the Authentication-Results header. */
public enum AuthResult {
    PASS,
    FAIL,
    SOFTFAIL,
    NEUTRAL,
    UNKNOWN
}

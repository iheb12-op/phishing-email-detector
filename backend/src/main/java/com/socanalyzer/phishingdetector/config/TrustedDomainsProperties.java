package com.socanalyzer.phishingdetector.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

/**
 * Configurable list of trusted domains used by DomainAnalyzer/SenderAnalyzer
 * for lookalike/typosquatting detection (requirement #6). This is a generic
 * mechanism — NOT hardcoded to a single company. Organizations deploying
 * this tool would populate it with their own brand + commonly-impersonated
 * partner domains.
 */
@Component
@ConfigurationProperties(prefix = "trusted")
public class TrustedDomainsProperties {

    private List<String> domains = new ArrayList<>();

    public List<String> getDomains() { return domains; }
    public void setDomains(List<String> domains) { this.domains = domains; }
}

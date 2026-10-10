package com.socanalyzer.phishingdetector.analyzer;

import com.socanalyzer.phishingdetector.model.Finding;
import com.socanalyzer.phishingdetector.model.ThreatIndicator;
import org.springframework.stereotype.Component;

import java.util.*;

/**
 * Maps findings to MITRE ATT&CK techniques (requirement #12). A technique
 * is only emitted when at least one finding with that mitreTechniqueId
 * exists ("sufficient evidence" — we never map a technique speculatively).
 *
 * EDUCATIONAL NOTE:
 *  MITRE ATT&CK is a globally shared knowledge base of adversary tactics
 *  and techniques used across the SOC/Threat Intel/Incident Response
 *  community as a common language. Mapping findings to it lets an analyst
 *  immediately understand "what phase of an attack is this?" and connects
 *  local findings to broader threat intelligence and detection coverage
 *  (e.g. "do we have detections for T1566.002 elsewhere in our stack?").
 */
@Component
public class MitreAttackMapper {

    private static final Map<String, String> TECHNIQUE_NAMES = Map.of(
            "T1566.001", "Phishing: Spearphishing Attachment",
            "T1566.002", "Phishing: Spearphishing Link",
            "T1566.003", "Phishing: Spearphishing via Service"
    );

    public List<ThreatIndicator> mapFindings(List<Finding> allFindings) {
        Map<String, List<Finding>> grouped = new LinkedHashMap<>();
        for (Finding f : allFindings) {
            if (f.getMitreTechniqueId() != null && TECHNIQUE_NAMES.containsKey(f.getMitreTechniqueId())) {
                grouped.computeIfAbsent(f.getMitreTechniqueId(), k -> new ArrayList<>()).add(f);
            }
        }

        List<ThreatIndicator> indicators = new ArrayList<>();
        for (Map.Entry<String, List<Finding>> entry : grouped.entrySet()) {
            ThreatIndicator ti = new ThreatIndicator();
            ti.setTechniqueId(entry.getKey());
            ti.setTechniqueName(TECHNIQUE_NAMES.get(entry.getKey()));
            List<String> titles = entry.getValue().stream().map(Finding::getTitle).toList();
            ti.setJustification("Supported by " + entry.getValue().size() + " finding(s): " + String.join("; ", titles));
            indicators.add(ti);
        }
        return indicators;
    }
}

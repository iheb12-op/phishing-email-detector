package com.socanalyzer.phishingdetector.repository;

import com.socanalyzer.phishingdetector.model.EmailAnalysis;
import com.socanalyzer.phishingdetector.model.Verdict;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;

import java.util.List;
import java.util.UUID;

public interface EmailAnalysisRepository extends JpaRepository<EmailAnalysis, UUID> {

    List<EmailAnalysis> findByVerdict(Verdict verdict);

    @Query("select avg(e.riskScore) from EmailAnalysis e")
    Double averageRiskScore();

    long countByVerdict(Verdict verdict);
}

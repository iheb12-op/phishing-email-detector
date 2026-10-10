-- Initial schema for the Phishing Email Detector (requirement #16).

CREATE TABLE email_analysis (
    id                  UUID PRIMARY KEY,
    analyzed_at         TIMESTAMP NOT NULL,
    from_address        VARCHAR(500),
    from_display_name   VARCHAR(500),
    to_address          VARCHAR(500),
    reply_to_address    VARCHAR(500),
    subject             VARCHAR(1000),
    message_id          VARCHAR(500),
    origin_date         VARCHAR(200),
    spf_result          VARCHAR(20) NOT NULL DEFAULT 'UNKNOWN',
    dkim_result         VARCHAR(20) NOT NULL DEFAULT 'UNKNOWN',
    dmarc_result        VARCHAR(20) NOT NULL DEFAULT 'UNKNOWN',
    risk_score          INTEGER NOT NULL DEFAULT 0,
    verdict             VARCHAR(30) NOT NULL DEFAULT 'SAFE',
    source_type         VARCHAR(30)
);

CREATE TABLE finding (
    id                  UUID PRIMARY KEY,
    analysis_id         UUID NOT NULL REFERENCES email_analysis(id) ON DELETE CASCADE,
    category            VARCHAR(30) NOT NULL,
    severity            VARCHAR(20) NOT NULL,
    title               VARCHAR(500),
    description         VARCHAR(2000),
    evidence            VARCHAR(2000),
    recommendation      VARCHAR(1000),
    score_impact        INTEGER NOT NULL DEFAULT 0,
    mitre_technique_id  VARCHAR(20)
);

CREATE TABLE extracted_url (
    id                  UUID PRIMARY KEY,
    analysis_id         UUID NOT NULL REFERENCES email_analysis(id) ON DELETE CASCADE,
    url                 VARCHAR(2048),
    domain              VARCHAR(500),
    risk                VARCHAR(20),
    reason              VARCHAR(1000),
    displayed_text      VARCHAR(500),
    domain_mismatch     BOOLEAN NOT NULL DEFAULT FALSE,
    uses_ip_address     BOOLEAN NOT NULL DEFAULT FALSE,
    is_shortener        BOOLEAN NOT NULL DEFAULT FALSE,
    is_punycode         BOOLEAN NOT NULL DEFAULT FALSE,
    uses_https          BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE email_attachment (
    id                    UUID PRIMARY KEY,
    analysis_id           UUID NOT NULL REFERENCES email_analysis(id) ON DELETE CASCADE,
    filename              VARCHAR(500),
    declared_mime_type    VARCHAR(200),
    size_bytes            BIGINT NOT NULL DEFAULT 0,
    risk                  VARCHAR(20),
    reason                VARCHAR(1000),
    double_extension      BOOLEAN NOT NULL DEFAULT FALSE,
    suspicious_extension  BOOLEAN NOT NULL DEFAULT FALSE,
    macro_enabled         BOOLEAN NOT NULL DEFAULT FALSE
);

CREATE TABLE threat_indicator (
    id              UUID PRIMARY KEY,
    analysis_id     UUID NOT NULL REFERENCES email_analysis(id) ON DELETE CASCADE,
    technique_id    VARCHAR(20),
    technique_name  VARCHAR(200),
    justification   VARCHAR(1000)
);

CREATE TABLE email_header (
    id              UUID PRIMARY KEY,
    analysis_id     UUID NOT NULL REFERENCES email_analysis(id) ON DELETE CASCADE,
    name            VARCHAR(200),
    header_value    VARCHAR(4000)
);

CREATE INDEX idx_finding_analysis_id ON finding(analysis_id);
CREATE INDEX idx_url_analysis_id ON extracted_url(analysis_id);
CREATE INDEX idx_attachment_analysis_id ON email_attachment(analysis_id);
CREATE INDEX idx_threat_analysis_id ON threat_indicator(analysis_id);
CREATE INDEX idx_header_analysis_id ON email_header(analysis_id);
CREATE INDEX idx_analysis_verdict ON email_analysis(verdict);

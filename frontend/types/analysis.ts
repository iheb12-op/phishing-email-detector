export type Severity = "LOW" | "MEDIUM" | "HIGH" | "CRITICAL";
export type Verdict = "SAFE" | "SUSPICIOUS" | "LIKELY_PHISHING" | "HIGH_CONFIDENCE_PHISHING";
export type AuthStatus = "PASS" | "FAIL" | "SOFTFAIL" | "NEUTRAL" | "UNKNOWN";

export interface Finding {
  id: string;
  category: string;
  severity: Severity;
  title: string;
  description: string;
  evidence: string;
  recommendation: string;
  scoreImpact: number;
  mitreTechniqueId: string | null;
}

export interface ExtractedUrl {
  id: string;
  url: string;
  domain: string | null;
  risk: Severity;
  reason: string;
  displayedText: string | null;
  domainMismatch: boolean;
  usesIpAddress: boolean;
  isShortener: boolean;
  isPunycode: boolean;
  usesHttps: boolean;
}

export interface AttachmentInfo {
  id: string;
  filename: string;
  declaredMimeType: string | null;
  sizeBytes: number;
  risk: Severity;
  reason: string;
  doubleExtension: boolean;
  suspiciousExtension: boolean;
  macroEnabled: boolean;
}

export interface MitreMapping {
  techniqueId: string;
  techniqueName: string;
  justification: string;
}

export interface EmailOverview {
  fromAddress: string | null;
  fromDisplayName: string | null;
  toAddress: string | null;
  replyToAddress: string | null;
  subject: string | null;
  messageId: string | null;
  date: string | null;
}

export interface AuthenticationSummary {
  spf: AuthStatus;
  dkim: AuthStatus;
  dmarc: AuthStatus;
}

export interface AnalysisResponse {
  id: string;
  analyzedAt: string;
  riskScore: number;
  verdict: Verdict;
  emailOverview: EmailOverview;
  authentication: AuthenticationSummary;
  findings: Finding[];
  urls: ExtractedUrl[];
  attachments: AttachmentInfo[];
  mitreMappings: MitreMapping[];
  recommendedActions: string[];
}

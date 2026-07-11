/**
 * Prepared demo artifact — ChatGPT vs SafeO side-by-side (not live ChatGPT).
 * Judges see why generic LLMs miss IDN homograph phishing.
 */
export const HOMOGRAPH_DEMO_URL = "https://ọpen-ạccess.com/login";

export const CHATGPT_DEMO_RESPONSE = {
  title: "ChatGPT",
  subtitle: "Generic answer — same depth for every user",
  verdict: "Looks safe",
  verdictClass: "safe",
  body: [
    "This appears to be a legitimate domain for an open-access login page.",
    "The hostname reads like \"open-access.com\" — a normal academic publishing site.",
    "I don't see obvious malware indicators in the URL structure.",
    "Recommendation: proceed if you were expecting this link.",
  ],
  footnote: "Prepared demo artifact — illustrates how LLMs normalize confusable Unicode visually.",
};

export function buildSafeoDemoSummary(scan) {
  if (!scan) return null;
  const url = scan.url_analysis || {};
  return {
    title: "SafeO",
    subtitle: "Role-adaptive forensic engine — same analysis, analyst depth available",
    verdict: scan.decision === "BLOCK" ? "UNSAFE" : scan.decision === "WARN" ? "CAUTION" : "SAFE",
    verdictClass: scan.decision === "BLOCK" ? "unsafe" : scan.decision === "WARN" ? "warn" : "safe",
    risk_score: scan.risk_score,
    uncertainty_score: scan.uncertainty_score,
    audit_hash: scan.audit_hash,
    mitre: scan.graph_evidence?.mitre_techniques || ["T1566.002"],
    flagged_chars: url.flagged_chars || [],
    host: url.host,
    patterns: scan.matched_patterns || [],
    explanations: scan.explanations || [],
  };
}

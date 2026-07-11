/**
 * SafeO Workflow Builder — node catalog.
 * status: real | partial | new | mock
 */

export const NODE_CATEGORIES = {
  control: "control",
  input: "input",
  detection: "detection",
  decision: "decision",
  output: "output",
};

export const NODE_CATALOG = [
  { id: "start", category: "control", label: "Start", subtitle: "Pipeline entry", status: "real", color: "#22c55e", fixed: false },
  { id: "end", category: "control", label: "End", subtitle: "Pipeline exit", status: "real", color: "#ef4444", fixed: false },

  { id: "erp_form", category: "input", label: "ERP form", subtitle: "Odoo field values at point of entry", status: "real", color: "#3b82f6" },
  { id: "api_payload", category: "input", label: "API payload", subtitle: "JSON / REST request body", status: "real", color: "#3b82f6" },
  { id: "whatsapp_message", category: "input", label: "WhatsApp message", subtitle: "WhatsApp Business text", status: "real", color: "#3b82f6" },
  { id: "website_input", category: "input", label: "Website input", subtitle: "Web form fields", status: "real", color: "#3b82f6" },
  { id: "free_text", category: "input", label: "Free text", subtitle: "Manual paste or typed input", status: "real", color: "#3b82f6" },
  { id: "url_scanner", category: "input", label: "URL scanner", subtitle: "IDN homograph · mixed script · phishing links", status: "real", color: "#3b82f6" },
  { id: "github_repo", category: "input", label: "GitHub repo", subtitle: "URL or zip — shallow clone scan", status: "new", color: "#3b82f6", locked: true },
  { id: "slack_message", category: "input", label: "Slack message", subtitle: "Channel or DM text", status: "new", color: "#3b82f6", locked: true },
  { id: "pdf_document", category: "input", label: "PDF / document", subtitle: "Upload, extract text, then scan", status: "new", color: "#3b82f6", locked: true },

  { id: "arabic_arabizi", category: "detection", label: "Arabic + Arabizi detector", subtitle: "Mixed script, digit obfuscation, Arabizi", status: "real", color: "#b45309" },
  { id: "language_script", category: "detection", label: "Language / script detector", subtitle: "Dialect presets + tenant n-gram samples", status: "partial", color: "#b45309" },
  { id: "architecture_scanner", category: "detection", label: "Architecture scanner", subtitle: "SQLi · XSS · SSRF · SSTI · entropy", status: "real", color: "#7c3aed" },
  { id: "erp_fraud", category: "detection", label: "ERP fraud detector", subtitle: "Invoice split · audit bypass · privilege abuse", status: "real", color: "#7c3aed" },
  { id: "prompt_injection", category: "detection", label: "Prompt injection detector", subtitle: "Instruction override · exfil · trust exploit", status: "real", color: "#7c3aed" },
  { id: "pii_scanner", category: "detection", label: "PII scanner", subtitle: "Email · phone · national ID · card patterns", status: "new", color: "#7c3aed", locked: true },
  { id: "github_repo_scanner", category: "detection", label: "GitHub repo scanner", subtitle: "Secrets · prompts in comments · per-file findings", status: "new", color: "#7c3aed", locked: true },

  {
    id: "risk_score",
    category: "decision",
    label: "Risk score + decision",
    subtitle: "Bayesian threshold · uncertainty · ALLOW / WARN / BLOCK",
    status: "real",
    color: "#111827",
    fixed: true,
    locked: true,
  },

  { id: "pdf_report", category: "output", label: "PDF report", subtitle: "Evidence · MITRE · remediation · audit hash", status: "new", color: "#0d9488", locked: true },
  { id: "whatsapp_reply", category: "output", label: "WhatsApp reply", subtitle: "Safe reply on BLOCK for WA sources", status: "real", color: "#22c55e" },
  { id: "human_review", category: "output", label: "Human review queue", subtitle: "WARN held for analyst approve/reject", status: "real", color: "#2563eb" },
  { id: "erp_block", category: "output", label: "ERP block", subtitle: "Stop transaction before Odoo persistence", status: "real", color: "#dc2626" },
  { id: "slack_alert", category: "output", label: "Slack alert", subtitle: "Webhook on WARN / BLOCK", status: "new", color: "#f97316", locked: true },
  { id: "jira_ticket", category: "output", label: "Jira ticket", subtitle: "Auto-create SEC ticket", status: "mock", color: "#6366f1", locked: true },
  { id: "siem_export", category: "output", label: "SIEM export", subtitle: "OTEL / Splunk forward", status: "mock", color: "#78716c", locked: true },
  { id: "email_alert", category: "output", label: "Email alert", subtitle: "SMTP on BLOCK", status: "mock", color: "#78716c", locked: true },
];

export const CATALOG_BY_ID = Object.fromEntries(NODE_CATALOG.map((n) => [n.id, n]));

export const PALETTE_SECTIONS = [
  { key: "input", title: "Input" },
  { key: "detection", title: "Detection" },
  { key: "output", title: "Output" },
];

const FIXED_NODE_TYPES = new Set(["start", "end", "risk_score"]);

/** Start, Risk Score, and End are always on canvas — user drags the rest and draws lines. */
export function emptyPipeline() {
  return {
    id: crypto.randomUUID(),
    name: "Untitled pipeline",
    observe_mode: true,
    nodes: [
      { id: "n_start", type: "start", x: 60, y: 280 },
      { id: "risk_score_center", type: "risk_score", x: 480, y: 280 },
      { id: "n_end", type: "end", x: 900, y: 280 },
    ],
    edges: [],
    viewport: { x: 0, y: 0, zoom: 1 },
  };
}

export function isFixedNode(type) {
  return FIXED_NODE_TYPES.has(type);
}

export function isComingSoon(status) {
  return status === "mock" || status === "new";
}

export function statusLabel(status) {
  if (status === "mock") return "Coming soon";
  if (status === "new") return "Coming soon";
  if (status === "partial") return "Partial";
  return null;
}

/** Optional example — user loads explicitly, not the default canvas. */
export function examplePipeline() {
  const riskId = "risk_score_center";
  return {
    id: crypto.randomUUID(),
    name: "Example pipeline",
    observe_mode: true,
    nodes: [
      { id: "n_start", type: "start", x: 40, y: 220 },
      { id: "n_api", type: "api_payload", x: 200, y: 200 },
      { id: "n_arabic", type: "arabic_arabizi", x: 400, y: 120 },
      { id: "n_arch", type: "architecture_scanner", x: 400, y: 300 },
      { id: riskId, type: "risk_score", x: 620, y: 200 },
      { id: "n_review", type: "human_review", x: 860, y: 140 },
      { id: "n_pdf", type: "pdf_report", x: 860, y: 280 },
      { id: "n_erp", type: "erp_block", x: 1080, y: 200 },
      { id: "n_end", type: "end", x: 1240, y: 220 },
    ],
    edges: [
      { id: "e1", from: "n_start", to: "n_api" },
      { id: "e2", from: "n_api", to: "n_arabic" },
      { id: "e3", from: "n_api", to: "n_arch" },
      { id: "e4", from: "n_arabic", to: riskId },
      { id: "e5", from: "n_arch", to: riskId },
      { id: "e6", from: riskId, to: "n_review" },
      { id: "e7", from: riskId, to: "n_pdf" },
      { id: "e8", from: "n_review", to: "n_erp" },
      { id: "e9", from: "n_pdf", to: "n_erp" },
      { id: "e10", from: "n_erp", to: "n_end" },
    ],
    viewport: { x: 0, y: 0, zoom: 1 },
  };
}

/**
 * Role-based presentation configs — same scan engine, different UI depth.
 */
export const ROLES = [
  {
    id: "non_technical",
    label: "Non-technical user",
    tagline: "I got a link — is it safe?",
    placeholder: "Paste a link someone sent you, e.g. https://example.com/login",
    inputHint: "Links, messages, anything you're unsure about",
  },
  {
    id: "security_analyst",
    label: "Security analyst",
    tagline: "Full MITRE mapping and evidence chain",
    placeholder: "Paste URL, payload, or attack sample for forensic breakdown",
    inputHint: "Any input — you'll see patterns, MITRE, uncertainty, audit hash",
  },
  {
    id: "erp_manager",
    label: "ERP manager",
    tagline: "Scan this invoice memo",
    placeholder: "Paste invoice memo, payment note, or vendor message",
    inputHint: "ERP fields, memos, wire-transfer requests",
  },
  {
    id: "developer",
    label: "Developer",
    tagline: "Scan API payload or GitHub repo",
    placeholder: 'Paste JSON body, curl payload, or repo URL',
    inputHint: "API payloads, code snippets, repo URLs",
  },
];

export const ROLE_BY_ID = Object.fromEntries(ROLES.map((r) => [r.id, r]));

export function inferSourceSystem(roleId, input) {
  const text = (input || "").trim();
  if (/^https?:\/\//i.test(text) || /^[\w.-]+\.[a-z]{2,}/i.test(text)) return "url_scanner";
  if (roleId === "erp_manager") return "erp";
  if (roleId === "developer") return "api";
  return "free_text";
}

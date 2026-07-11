"""
Attack Pattern Knowledge Graph — structured threat intelligence for ForensicsAgent.

Each node represents an attack family and carries:
  - children:        variant sub-types (e.g. blind SQLi, stored XSS)
  - mitre:           MITRE ATT&CK technique IDs
  - cve_examples:    representative CVE identifiers
  - remediation_ids: IDs that map to concrete remediation playbooks
  - description:     human-readable summary
  - indicators:      canonical indicator strings for pattern→node matching

Inspired by Cascade's KG-grounded agents — diagnoses are traceable and
verifiable because ForensicsAgent injects graph evidence rather than
reasoning from free text alone.

Usage
-----
  from .attack_graph import query_graph

  evidence = query_graph(matched_patterns)   # → AttackEvidence | None
  if evidence:
      forensics_result["graph_evidence"] = evidence.to_dict()
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

# ── Node definition ───────────────────────────────────────────────────────────

@dataclass
class AttackNode:
    attack_id: str
    description: str
    children: List[str]
    mitre: List[str]
    cve_examples: List[str]
    remediation_ids: List[str]
    indicators: List[str]          # substrings that trigger this node


@dataclass
class AttackEvidence:
    """Structured evidence injected into ForensicsAgent results."""
    attack_id: str
    description: str
    matched_children: List[str]    # variants detected in this request
    mitre_techniques: List[str]
    cve_examples: List[str]
    remediation_ids: List[str]
    confidence_boost: float        # +delta applied to ForensicsAgent confidence

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


# ── Knowledge graph ───────────────────────────────────────────────────────────

_GRAPH: Dict[str, AttackNode] = {

    "sql_injection": AttackNode(
        attack_id="sql_injection",
        description="Attacker injects SQL directives into application queries to manipulate or exfiltrate database content.",
        children=["blind_sqli", "time_based_sqli", "union_based_sqli", "error_based_sqli", "stacked_queries"],
        mitre=["T1190", "T1059.004"],
        cve_examples=["CVE-2012-1823", "CVE-2019-2215", "CVE-2021-44228"],
        remediation_ids=["REM-001", "REM-002"],
        indicators=["sql_injection", "union select", "or 1=1", "drop table", "'; --", "xp_cmdshell"],
    ),

    "blind_sqli": AttackNode(
        attack_id="blind_sqli",
        description="SQL injection where results are not directly visible; attacker infers data from application behavior.",
        children=[],
        mitre=["T1190"],
        cve_examples=["CVE-2019-11223"],
        remediation_ids=["REM-001"],
        indicators=["blind", "boolean-based", "time-based"],
    ),

    "union_based_sqli": AttackNode(
        attack_id="union_based_sqli",
        description="Uses UNION SELECT to append attacker-controlled query results to the original query output.",
        children=[],
        mitre=["T1190"],
        cve_examples=["CVE-2021-27561"],
        remediation_ids=["REM-001", "REM-002"],
        indicators=["union select", "union all select", "UNION SELECT"],
    ),

    "xss": AttackNode(
        attack_id="xss",
        description="Attacker injects client-side scripts into web pages viewed by other users.",
        children=["stored_xss", "reflected_xss", "dom_based_xss"],
        mitre=["T1059.007"],
        cve_examples=["CVE-2021-26084", "CVE-2020-11022", "CVE-2022-1388"],
        remediation_ids=["REM-003", "REM-004"],
        indicators=["xss", "<script>", "javascript:", "onerror=", "onload=", "alert(", "document.cookie"],
    ),

    "stored_xss": AttackNode(
        attack_id="stored_xss",
        description="Malicious script is persisted in the application database and served to all users.",
        children=[],
        mitre=["T1059.007"],
        cve_examples=["CVE-2022-0540"],
        remediation_ids=["REM-003"],
        indicators=["stored", "persistent xss"],
    ),

    "reflected_xss": AttackNode(
        attack_id="reflected_xss",
        description="Malicious script is reflected from the server in an immediate response.",
        children=[],
        mitre=["T1059.007"],
        cve_examples=["CVE-2021-40438"],
        remediation_ids=["REM-003", "REM-004"],
        indicators=["reflected", "search=", "q=<script>"],
    ),

    "dom_based_xss": AttackNode(
        attack_id="dom_based_xss",
        description="Script injection occurs entirely in the browser DOM without server involvement.",
        children=[],
        mitre=["T1059.007"],
        cve_examples=["CVE-2022-26134"],
        remediation_ids=["REM-004"],
        indicators=["dom", "document.write", "innerHTML", "location.hash"],
    ),

    "command_injection": AttackNode(
        attack_id="command_injection",
        description="Attacker passes OS commands through application input to execute on the host.",
        children=["shell_injection", "argument_injection"],
        mitre=["T1059", "T1203"],
        cve_examples=["CVE-2021-44228", "CVE-2020-14882", "CVE-2014-6271"],
        remediation_ids=["REM-005"],
        indicators=["command_injection", "; ls", "| id", "`id`", "$(id)", "&&", "||", "/bin/sh", "cmd.exe"],
    ),

    "path_traversal": AttackNode(
        attack_id="path_traversal",
        description="Attacker traverses directory structure to access files outside the intended path.",
        children=["lfi", "rfi"],
        mitre=["T1083"],
        cve_examples=["CVE-2021-41773", "CVE-2019-18935"],
        remediation_ids=["REM-006"],
        indicators=["path_traversal", "../", "..\\", "%2e%2e", "/etc/passwd", "/proc/self"],
    ),

    "ssrf": AttackNode(
        attack_id="ssrf",
        description="Server-Side Request Forgery — attacker coerces the server to make requests to internal services.",
        children=["cloud_metadata_ssrf", "internal_port_scan"],
        mitre=["T1090", "T1071"],
        cve_examples=["CVE-2021-26855", "CVE-2022-22963"],
        remediation_ids=["REM-007"],
        indicators=["ssrf", "169.254.169.254", "http://localhost", "http://127.0.0.1", "internal", "metadata"],
    ),

    "prompt_injection": AttackNode(
        attack_id="prompt_injection",
        description="Attacker overrides AI assistant system prompts to hijack model behavior.",
        children=["direct_prompt_injection", "indirect_prompt_injection"],
        mitre=["T1059", "T1195"],
        cve_examples=[],
        remediation_ids=["REM-008"],
        indicators=["prompt_injection", "ignore previous", "system prompt", "disregard instructions", "you are now"],
    ),

    "ssti_template_injection": AttackNode(
        attack_id="ssti_template_injection",
        description="Server-Side Template Injection — attacker exploits template engines to execute arbitrary code.",
        children=[],
        mitre=["T1059", "T1203"],
        cve_examples=["CVE-2019-8341", "CVE-2022-22947"],
        remediation_ids=["REM-009"],
        indicators=["ssti_template_injection", "{{7*7}}", "${7*7}", "#{7*7}", "<%=7*7%>"],
    ),

    "erp_financial_fraud": AttackNode(
        attack_id="erp_financial_fraud",
        description="Attempt to commit financial fraud or embezzlement within ERP system workflows.",
        children=["invoice_manipulation", "payment_redirect"],
        mitre=["T1565", "T1491"],
        cve_examples=[],
        remediation_ids=["REM-010", "REM-011"],
        indicators=["erp_financial_fraud", "wire transfer", "off-book", "avoid audit", "duplicate payment"],
    ),

    "erp_data_exfiltration": AttackNode(
        attack_id="erp_data_exfiltration",
        description="Bulk extraction of sensitive records from ERP databases.",
        children=[],
        mitre=["T1530", "T1213"],
        cve_examples=[],
        remediation_ids=["REM-012"],
        indicators=["erp_data_exfiltration", "bulk export", "download all", "extract records"],
    ),

    "erp_privilege_abuse": AttackNode(
        attack_id="erp_privilege_abuse",
        description="Escalation or abuse of ERP user privileges to bypass access controls.",
        children=[],
        mitre=["T1078", "T1134"],
        cve_examples=[],
        remediation_ids=["REM-010"],
        indicators=["erp_privilege_abuse", "grant admin", "bypass approval", "override limit"],
    ),

    "idn_homograph_phishing": AttackNode(
        attack_id="idn_homograph_phishing",
        description=(
            "Internationalized domain name (IDN) homograph attack — confusable Unicode characters "
            "in the hostname disguise a phishing URL as a trusted domain."
        ),
        children=["arabic_digit_url", "mixed_script_hostname"],
        mitre=["T1566.002", "T1204.001"],
        cve_examples=[],
        remediation_ids=["REM-013"],
        indicators=[
            "idn_homograph",
            "homograph",
            "mixed_script",
            "punycode",
            "xn--",
            "unicode",
        ],
    ),

    "mixed_script_hostname": AttackNode(
        attack_id="mixed_script_hostname",
        description="Hostname mixes Latin with Arabic, Cyrillic, or other scripts to evade visual inspection.",
        children=[],
        mitre=["T1566.002"],
        cve_examples=[],
        remediation_ids=["REM-013"],
        indicators=["mixed_script_hostname", "mixed_script"],
    ),

    "arabic_digit_url": AttackNode(
        attack_id="arabic_digit_url",
        description="Arabic-Indic or Eastern Arabic digits in URL to bypass Latin-only filters.",
        children=[],
        mitre=["T1566.002"],
        cve_examples=[],
        remediation_ids=["REM-013"],
        indicators=["arabic_indic_digits_in_url", "arabic_digits"],
    ),
}

# ── Remediation playbook registry ─────────────────────────────────────────────

_REMEDIATION_PLAYBOOKS: Dict[str, str] = {
    "REM-001": "OWASP SQL Injection Prevention — use parameterised queries and ORMs; disable detailed DB errors.",
    "REM-002": "Apply principle of least privilege to DB accounts; audit via INFORMATION_SCHEMA.",
    "REM-003": "OWASP XSS Prevention — context-aware output encoding; Content-Security-Policy header.",
    "REM-004": "Enable Trusted Types; sanitise DOM sinks (innerHTML, document.write).",
    "REM-005": "OWASP OS Command Injection — whitelist allowed commands; use subprocess with arg arrays, not shell=True.",
    "REM-006": "OWASP Path Traversal — canonicalise paths; restrict chroot/jail; validate against allowlist.",
    "REM-007": "SSRF prevention — block private IP ranges at network layer; use metadata service IMDSv2.",
    "REM-008": "Prompt injection — use system prompt hardening; validate LLM outputs before acting on them.",
    "REM-009": "SSTI prevention — use safe template engines; sandbox execution; disable dangerous template features.",
    "REM-010": "ERP access control review — audit role assignments; enforce segregation of duties.",
    "REM-011": "Enable dual-approval workflows for financial transactions above threshold.",
    "REM-012": "Implement rate limiting and DLP controls on bulk data export endpoints.",
    "REM-013": "Block IDN homograph URLs at the gateway; display punycode in browsers; train users on link verification.",
}

# ── Query API ─────────────────────────────────────────────────────────────────

def query_graph(matched_patterns: List[str]) -> Optional[AttackEvidence]:
    """
    Given a list of matched_patterns strings (from keyword_detector),
    find the best matching attack node and return structured evidence.

    Pattern format: ``"category: 'snippet'"`` or bare ``"category"``.
    """
    if not matched_patterns:
        return None

    # Extract category tokens from patterns
    categories: List[str] = []
    raw_text = " ".join(matched_patterns).lower()
    for pat in matched_patterns:
        cat = pat.split(":")[0].strip().lower()
        categories.append(cat)

    # Score each node: match by category name or indicator substring
    scores: Dict[str, int] = {}
    for node_id, node in _GRAPH.items():
        score = 0
        # Direct category match
        if node_id in categories:
            score += 10
        # Category match in parent's children list
        for child in node.children:
            if child in categories:
                score += 5
        # Indicator substring match against raw pattern text
        for ind in node.indicators:
            if ind.lower() in raw_text:
                score += 2
        if score:
            scores[node_id] = score

    if not scores:
        return None

    best_id = max(scores, key=lambda k: scores[k])
    node = _GRAPH[best_id]

    # Detect which children variants are present
    matched_children = [
        child for child in node.children
        if any(child.replace("_", " ") in raw_text or child in raw_text for _ in [None])
    ]

    confidence_boost = min(0.05 * scores[best_id] / 10, 0.10)  # up to +0.10

    return AttackEvidence(
        attack_id=best_id,
        description=node.description,
        matched_children=matched_children,
        mitre_techniques=node.mitre,
        cve_examples=node.cve_examples,
        remediation_ids=node.remediation_ids,
        confidence_boost=round(confidence_boost, 3),
    )


def get_remediation_playbooks(remediation_ids: List[str]) -> Dict[str, str]:
    """Resolve remediation IDs to their playbook descriptions."""
    return {rid: _REMEDIATION_PLAYBOOKS[rid] for rid in remediation_ids if rid in _REMEDIATION_PLAYBOOKS}

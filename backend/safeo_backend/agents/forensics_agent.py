"""
ForensicsAgent — reconstructs the attack from matched patterns and entropy signals.

Primary logic is deterministic rule-based (zero-dependency).
When SAFEO_ENABLE_AGENT_LLM=true the agent falls back to the local vLLM-compatible
endpoint if Fireworks Gemma is unavailable. Primary LLM path uses Gemma 3 4B on
Fireworks (AMD infrastructure) via call_fireworks_gemma().

Graph grounding: ForensicsAgent always queries the attack_graph knowledge graph
by matched_patterns and injects structured evidence (MITRE IDs, CVE links,
remediation playbook IDs) into the result. Diagnoses are therefore traceable
and verifiable — not free-text hallucination.

agent_post logging is handled by investigation_room.py.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

from .attack_graph import query_graph, get_remediation_playbooks

logger = logging.getLogger("safeo.forensics_agent")

_last_forensics_model_used: Optional[str] = None


def get_last_forensics_model_used() -> Optional[str]:
    """Most recent ForensicsAgent model_used value (for UI status badge)."""
    return _last_forensics_model_used


def _set_last_forensics_model_used(model_used: str) -> None:
    global _last_forensics_model_used
    _last_forensics_model_used = model_used


_OBFUSCATION_HINTS = {
    "decoded:": "URL-encoded payload (iterative URL-decode exposed attack)",
    "multilingual_evasion": "Non-Latin script obfuscation (Arabic/Urdu/Arabizi)",
    "%": "Percent-encoding",
    "base64": "Base64 encoding",
    "\\x": "Hex escape sequences",
    "&#": "HTML entity encoding",
}

_INTENT_MAP = {
    "sql_injection":           "Extract or destroy database records",
    "xss":                     "Inject malicious scripts into browser",
    "ssti_template_injection": "Execute code via server-side template engine",
    "prompt_injection":        "Override AI assistant instructions",
    "command_injection":       "Execute OS commands on the server",
    "path_traversal":          "Read restricted filesystem paths",
    "ssrf":                    "Probe internal services or cloud metadata",
    "obfuscation":             "Evade detection via encoding",
    "erp_financial_fraud":     "Commit financial fraud or embezzlement in ERP",
    "erp_data_exfiltration":   "Exfiltrate bulk records from ERP database",
    "erp_privilege_abuse":     "Escalate privileges or bypass ERP controls",
    "erp_social_engineering":  "Manipulate ERP users or approvers",
}


class ForensicsAgent:
    name = "ForensicsAgent"

    def analyse(
        self,
        payload: str,
        normalised_text: str,
        script_detected: str,
        matched_patterns: List[str],
        entropy: float = 0.0,
        meta: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        meta = meta or {}

        attack_type = "unknown"
        for pat in matched_patterns:
            cat = pat.split(":")[0] if ":" in pat else pat
            if cat in _INTENT_MAP:
                attack_type = cat
                break

        obfuscation: Optional[str] = None
        raw_pats_str = " ".join(matched_patterns + [payload])
        for hint, desc in _OBFUSCATION_HINTS.items():
            if hint in raw_pats_str:
                obfuscation = desc
                break
        if script_detected not in ("latin", "unknown") and not obfuscation:
            obfuscation = f"Non-Latin script ({script_detected})"

        intent = _INTENT_MAP.get(attack_type, "Malicious or suspicious input intent")

        confidence = 0.90
        if not matched_patterns:
            confidence = 0.55
        elif all("multilingual" in p for p in matched_patterns):
            confidence = 0.70

        steps = []
        if obfuscation:
            steps.append(f"Payload encoded using {obfuscation}")
        if matched_patterns:
            steps.append(f"Matched signatures: {', '.join(matched_patterns[:3])}")
        steps.append(f"Likely intent: {intent}")
        if entropy > 0.72:
            steps.append(f"High entropy ({entropy:.2f}) suggests automated generation")

        result: Dict[str, Any] = {
            "attack_type": attack_type,
            "obfuscation_method": obfuscation,
            "matched_signatures": matched_patterns[:8],
            "attack_timeline": " → ".join(steps),
            "confidence": round(confidence, 2),
            "model_used": "rule-based",
        }

        # ── Knowledge graph grounding ─────────────────────────────────────────
        # Query the attack pattern graph to inject traceable structured evidence.
        graph_evidence = query_graph(matched_patterns)
        if graph_evidence:
            result["graph_evidence"] = graph_evidence.to_dict()
            result["mitre_techniques"] = graph_evidence.mitre_techniques
            result["remediation_ids"] = graph_evidence.remediation_ids
            result["remediation_playbooks"] = get_remediation_playbooks(graph_evidence.remediation_ids)
            # Graph-grounded confidence boost (bounded to max 0.98)
            result["confidence"] = round(min(confidence + graph_evidence.confidence_boost, 0.98), 3)
            # Prefer graph's authoritative attack_id when it matches more specifically
            if graph_evidence.attack_id != "unknown":
                result["attack_type"] = graph_evidence.attack_id

        # ── LLM augmentation — Fireworks Gemma (AMD) first, local fallback ───
        from ..config.amd_config import (
            AGENT_LLM_API_KEY,
            AGENT_LLM_SERVER_URL,
            ENABLE_AGENT_LLM,
            FIREWORKS_API_KEY,
            FORENSICS_AGENT_MODEL,
        )

        gemma_prompt = self._build_gemma_prompt(
            payload=normalised_text or payload,
            attack_type=result["attack_type"],
            matched_patterns=matched_patterns,
            entropy=entropy,
            graph_evidence=result.get("graph_evidence"),
        )
        gemma_text: Optional[str] = None
        if FIREWORKS_API_KEY or self._fireworks_dry_run():
            gemma_text = self._try_fireworks_gemma(gemma_prompt)

        if gemma_text:
            llm_result = self._parse_gemma_response(gemma_text)
            if llm_result:
                result.update(llm_result)
                result["model_used"] = "fireworks-gemma"
                _set_last_forensics_model_used("fireworks-gemma")
        elif ENABLE_AGENT_LLM:
            llm_result = self._llm_augment(
                payload=normalised_text or payload,
                attack_type=result["attack_type"],
                matched_patterns=matched_patterns,
                entropy=entropy,
                graph_evidence=result.get("graph_evidence"),
                model=FORENSICS_AGENT_MODEL,
                server_url=AGENT_LLM_SERVER_URL,
                api_key=AGENT_LLM_API_KEY,
            )
            if llm_result:
                result.update(llm_result)
                result["model_used"] = "local-fallback"
                _set_last_forensics_model_used("local-fallback")

        return result

    @staticmethod
    def _fireworks_dry_run() -> bool:
        import os
        return os.environ.get("FIREWORKS_DRY_RUN", "").strip().lower() == "true"

    @staticmethod
    def _build_gemma_prompt(
        payload: str,
        attack_type: str,
        matched_patterns: List[str],
        entropy: float,
        graph_evidence: Optional[Dict[str, Any]],
    ) -> str:
        context = json.dumps({
            "payload_excerpt": (payload or "")[:500],
            "attack_type_detected": attack_type,
            "matched_patterns": matched_patterns[:8],
            "entropy": round(entropy, 3),
            "graph_evidence": graph_evidence,
        })
        return (
            "You are a cybersecurity forensics analyst. Given a suspicious payload, "
            "matched patterns, and graph evidence, return a JSON object with keys: "
            "attack_type (string), attack_timeline (string), mitre_techniques (list of strings), "
            "confidence (float 0-1), chain_of_thought (string — 2-4 sentence reasoning trace). "
            "Ground your analysis in the provided graph evidence.\n\n"
            f"Input:\n{context}"
        )

    @staticmethod
    def _try_fireworks_gemma(prompt: str) -> Optional[str]:
        try:
            import asyncio

            from ..core.ml.fireworks_gemma import call_fireworks_gemma

            return asyncio.run(call_fireworks_gemma(prompt))
        except Exception as exc:
            logger.debug("ForensicsAgent Fireworks Gemma failed: %s", exc)
            return None

    @staticmethod
    def _parse_gemma_response(raw_text: str) -> Optional[Dict[str, Any]]:
        text = (raw_text or "").strip()
        if not text:
            return None
        if text.startswith("```"):
            lines = text.splitlines()
            if lines and lines[0].startswith("```"):
                lines = lines[1:]
            if lines and lines[-1].strip() == "```":
                lines = lines[:-1]
            text = "\n".join(lines).strip()
        try:
            return json.loads(text)
        except json.JSONDecodeError as exc:
            logger.debug("ForensicsAgent Gemma JSON parse failed: %s", exc)
            return None

    @staticmethod
    def _llm_augment(
        payload: str,
        attack_type: str,
        matched_patterns: List[str],
        entropy: float,
        graph_evidence: Optional[Dict[str, Any]],
        model: str,
        server_url: str,
        api_key: str,
    ) -> Optional[Dict[str, Any]]:
        """Query DeepSeek-R1 for chain-of-thought reasoning + MITRE mapping."""
        try:
            from openai import OpenAI

            client = OpenAI(base_url=server_url, api_key=api_key)
            system = (
                "You are a cybersecurity forensics analyst using chain-of-thought reasoning. "
                "Given a suspicious payload, matched patterns, and graph evidence, return a JSON "
                "object with keys: attack_type (string), attack_timeline (string), "
                "mitre_techniques (list of strings), confidence (float 0-1), "
                "chain_of_thought (string — 2-4 sentence reasoning trace). "
                "Ground your analysis in the provided graph evidence."
            )
            user = json.dumps({
                "payload_excerpt": (payload or "")[:500],
                "attack_type_detected": attack_type,
                "matched_patterns": matched_patterns[:8],
                "entropy": round(entropy, 3),
                "graph_evidence": graph_evidence,
            })
            resp = client.chat.completions.create(
                model=model,
                temperature=0,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                response_format={"type": "json_object"},
                timeout=10,
            )
            raw = resp.choices[0].message.content or "{}"
            return json.loads(raw)
        except Exception as exc:
            logger.debug("ForensicsAgent LLM augment failed: %s", exc)
            return None

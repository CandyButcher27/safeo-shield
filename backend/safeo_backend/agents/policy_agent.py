"""
PolicyAgent — maps a risk decision to violated compliance policies by jurisdiction.

Primary logic is deterministic rule-based (zero-dependency).
When SAFEO_ENABLE_AGENT_LLM=true the agent additionally queries
Llama-3-70B-Instruct via the vLLM-compatible endpoint for richer policy
citation and nuanced severity reasoning, then merges that into the result.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger("safeo.policy_agent")

_RULES: Dict[str, Dict[str, Any]] = {
    "UAE": {
        "block_threshold": 0.60,
        "warn_threshold":  0.30,
        "policies": [
            "UAE Cybercrime Law (Federal Law No. 34/2021)",
            "UAE Personal Data Protection Law (Federal Decree-Law No. 45/2021)",
            "UAE Critical Infrastructure Protection Regulations",
        ],
        "severity_map": {"block": "critical", "warn": "high", "allow": "info"},
    },
    "EU": {
        "block_threshold": 0.65,
        "warn_threshold":  0.35,
        "policies": [
            "GDPR Article 32 — Security of Processing",
            "NIS2 Directive",
            "EU Cybersecurity Act",
        ],
        "severity_map": {"block": "critical", "warn": "medium", "allow": "low"},
    },
    "US": {
        "block_threshold": 0.70,
        "warn_threshold":  0.40,
        "policies": [
            "NIST Cybersecurity Framework",
            "SOX Section 302/404 (financial data)",
            "CCPA (if California data subjects)",
        ],
        "severity_map": {"block": "high", "warn": "medium", "allow": "low"},
    },
    "Global": {
        "block_threshold": 0.70,
        "warn_threshold":  0.40,
        "policies": [
            "ISO/IEC 27001 Control A.14.2.5",
            "OWASP Top 10",
        ],
        "severity_map": {"block": "high", "warn": "medium", "allow": "low"},
    },
}


class PolicyAgent:
    name = "PolicyAgent"

    def check(
        self,
        payload: str,
        context: Dict[str, Any],
        normalised_text: str,
        risk_score: float,
        decision: str,
    ) -> Dict[str, Any]:
        jurisdiction = (context.get("jurisdiction") or "Global").upper()
        rules = _RULES.get(jurisdiction, _RULES["Global"])
        violated: List[str] = []
        dec_lower = (decision or "allow").lower()

        if risk_score >= rules["block_threshold"]:
            violated = rules["policies"]
        elif risk_score >= rules["warn_threshold"]:
            violated = rules["policies"][:1]

        severity = rules["severity_map"].get(dec_lower, "info")
        if not violated:
            recommendation = "No policy action required — input within acceptable risk threshold."
        elif dec_lower == "block":
            recommendation = "Block and log. Escalate to compliance team within 24 hours."
        else:
            recommendation = "Flag for manual review. Retain audit evidence per data retention policy."

        result: Dict[str, Any] = {
            "policies_violated": violated,
            "jurisdiction": jurisdiction,
            "severity": severity,
            "recommendation": recommendation,
            "model_used": "rule-based",
        }

        # LLM augmentation — Llama-3-70B for richer citation & nuanced severity
        from ..config.amd_config import (
            AGENT_LLM_API_KEY,
            AGENT_LLM_SERVER_URL,
            ENABLE_AGENT_LLM,
            POLICY_AGENT_MODEL,
        )
        if ENABLE_AGENT_LLM:
            llm_result = self._llm_augment(
                payload=normalised_text or payload,
                jurisdiction=jurisdiction,
                violated=violated,
                severity=severity,
                risk_score=risk_score,
                model=POLICY_AGENT_MODEL,
                server_url=AGENT_LLM_SERVER_URL,
                api_key=AGENT_LLM_API_KEY,
            )
            if llm_result:
                result.update(llm_result)
                result["model_used"] = POLICY_AGENT_MODEL

        return result

    @staticmethod
    def _llm_augment(
        payload: str,
        jurisdiction: str,
        violated: List[str],
        severity: str,
        risk_score: float,
        model: str,
        server_url: str,
        api_key: str,
    ) -> Optional[Dict[str, Any]]:
        """Query Llama-3-70B for richer policy citations. Returns partial result or None."""
        try:
            from openai import OpenAI

            client = OpenAI(base_url=server_url, api_key=api_key)
            system = (
                "You are a cybersecurity compliance expert. Given a suspicious payload, "
                "jurisdiction, already-identified violated policies and severity, return a JSON "
                "object with keys: policies_violated (list of strings), severity (string), "
                "recommendation (string), llm_notes (string with 1-2 sentence rationale). "
                "Be concise and cite specific article numbers where possible."
            )
            user = json.dumps({
                "jurisdiction": jurisdiction,
                "risk_score": round(risk_score, 3),
                "severity_detected": severity,
                "policies_already_flagged": violated,
                "payload_excerpt": (payload or "")[:500],
            })
            resp = client.chat.completions.create(
                model=model,
                temperature=0,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                response_format={"type": "json_object"},
                timeout=8,
            )
            raw = resp.choices[0].message.content or "{}"
            return json.loads(raw)
        except Exception as exc:
            logger.debug("PolicyAgent LLM augment failed: %s", exc)
            return None

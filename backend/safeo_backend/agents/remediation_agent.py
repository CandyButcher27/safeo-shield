"""
RemediationAgent — proposes the safest automated or human-gated remediation action.

Primary logic is deterministic rule-based (zero-dependency).
When SAFEO_ENABLE_AGENT_LLM=true the agent additionally queries GPT-4o-mini
via the vLLM-compatible endpoint for structured action lists and richer
step-by-step remediation guidance.

auto_execute=True  → safe to execute immediately (block_input).
irreversible=True  → requires human approval before execution (suspend_user).
agent_post logging is handled by investigation_room.py.
"""
from __future__ import annotations

import json
import logging
from typing import Any, Dict, Optional

logger = logging.getLogger("safeo.remediation_agent")


class RemediationAgent:
    name = "RemediationAgent"

    def propose(
        self,
        policy_result: Dict[str, Any],
        forensics_result: Dict[str, Any],
        behavior_score: float,
        risk_score: float,
    ) -> Dict[str, Any]:
        attack_type  = forensics_result.get("attack_type", "unknown")
        severity     = policy_result.get("severity", "info")
        irreversible = False
        auto_execute = False

        if behavior_score >= 0.70 and risk_score >= 0.80:
            action = "suspend_user"
            irreversible = True
            auto_execute = False
            reason = (
                f"Behavioral anomaly (score={behavior_score:.2f}) combined with "
                f"high-risk payload (score={risk_score:.2f}). "
                "User session should be suspended pending security review."
            )
        elif risk_score >= 0.85 or severity == "critical":
            action = "block_input"
            irreversible = False
            auto_execute = True
            reason = (
                f"High-confidence {attack_type} attack (risk={risk_score:.2f}, "
                f"severity={severity}). Input blocked automatically."
            )
        elif risk_score >= 0.65 or severity in ("high", "critical"):
            action = "require_mfa"
            irreversible = False
            auto_execute = True
            reason = (
                f"Elevated risk ({attack_type}, score={risk_score:.2f}). "
                "Require step-up MFA before allowing action."
            )
        else:
            action = "flag_for_review"
            irreversible = False
            auto_execute = False
            reason = (
                f"Moderate risk ({attack_type}, score={risk_score:.2f}). "
                "Flagged for security team manual review."
            )

        result: Dict[str, Any] = {
            "action": action,
            "irreversible": irreversible,
            "reason": reason,
            "auto_execute": auto_execute,
            "model_used": "rule-based",
        }

        # LLM augmentation — GPT-4o-mini for structured action lists
        from ..config.amd_config import (
            AGENT_LLM_API_KEY,
            AGENT_LLM_SERVER_URL,
            ENABLE_AGENT_LLM,
            REMEDIATION_AGENT_MODEL,
        )
        if ENABLE_AGENT_LLM:
            llm_result = self._llm_augment(
                attack_type=attack_type,
                action=action,
                reason=reason,
                severity=severity,
                risk_score=risk_score,
                model=REMEDIATION_AGENT_MODEL,
                server_url=AGENT_LLM_SERVER_URL,
                api_key=AGENT_LLM_API_KEY,
            )
            if llm_result:
                result.update(llm_result)
                result["model_used"] = REMEDIATION_AGENT_MODEL

        return result

    @staticmethod
    def _llm_augment(
        attack_type: str,
        action: str,
        reason: str,
        severity: str,
        risk_score: float,
        model: str,
        server_url: str,
        api_key: str,
    ) -> Optional[Dict[str, Any]]:
        """Query GPT-4o-mini for structured remediation steps. Returns partial result or None."""
        try:
            from openai import OpenAI

            client = OpenAI(base_url=server_url, api_key=api_key)
            system = (
                "You are a security remediation expert. Given an attack event, return a JSON "
                "object with keys: action (string), reason (string), "
                "remediation_steps (list of strings, 3-5 concrete steps), "
                "references (list of strings, OWASP/CVE/NIST links). Be concise."
            )
            user = json.dumps({
                "attack_type": attack_type,
                "proposed_action": action,
                "severity": severity,
                "risk_score": round(risk_score, 3),
                "rule_reason": reason,
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
            logger.debug("RemediationAgent LLM augment failed: %s", exc)
            return None

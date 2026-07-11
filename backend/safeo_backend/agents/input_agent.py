import re
from typing import Dict, Any
from ..core.ml.risk_scorer import calculate_risk_score
from ..models.schemas import AgentResult


class InputAgent:
    name = "InputShield"
    description = "Primary input analysis agent — ML + rule-based threat detection"

    def analyze(self, text: str, context: Dict[str, Any] = {}) -> AgentResult:
        risk_score, decision, patterns, _, _meta = calculate_risk_score(text)
        confidence = min(0.70 + len(patterns) * 0.05 + min(len(text) / 500, 0.10), 1.0)
        return AgentResult(
            agent_name=self.name,
            status="triggered" if risk_score >= 0.30 else "active",
            decision=decision,
            confidence=round(confidence, 2),
            detected_patterns=patterns[:5],
        )

    def sanitize(self, text: str) -> str:
        text = re.sub(r"<script[^>]*>.*?</script>", "[SCRIPT_REMOVED]", text, flags=re.I | re.S)
        text = re.sub(r'\bon\w+\s*=\s*["\'][^"\']*["\']', "[EVENT_REMOVED]", text, flags=re.I)
        text = re.sub(r"(?i)(union\s+select|drop\s+table|insert\s+into)", "[SQL_BLOCKED]", text)
        text = re.sub(r"(?i)(ignore\s+(previous|prior)\s+instructions?)", "[PROMPT_BLOCKED]", text)
        text = re.sub(r"(?i)(;\s*(ls|cat|rm|wget|curl)\s)", "[CMD_BLOCKED]", text)
        return text

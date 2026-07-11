import re
from ..models.schemas import AgentResult

SENSITIVE_PATTERNS = {
    "credit_card": (r"\b(?:\d{4}[-\s]?){3}\d{4}\b", "[CREDIT_CARD_MASKED]"),
    "ssn": (r"\b\d{3}-\d{2}-\d{4}\b", "[SSN_MASKED]"),
    "aws_key": (r"AKIA[0-9A-Z]{16}", "[AWS_KEY_MASKED]"),
    "private_key": (r"-----BEGIN (RSA |EC )?PRIVATE KEY-----", "[PRIVATE_KEY_MASKED]"),
    "bearer_token": (r"(?i)bearer\s+([a-zA-Z0-9\-._~+/]{20,}=*)", "Bearer [TOKEN_MASKED]"),
    "api_key": (
        r"(?i)(api[_\s]?key|secret[_\s]?key)\s*[:=]\s*['\"]?([a-zA-Z0-9\-_]{16,})['\"]?",
        r"\1: [API_KEY_MASKED]",
    ),
    "password": (
        r"(?i)(password)\s*[:=]\s*['\"]?(\S{6,})['\"]?",
        r"\1: [PASSWORD_MASKED]",
    ),
    "bulk_email": (
        r"(?:[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}(?:\s*[,;]\s*)){2,}",
        "[BULK_EMAILS_MASKED]",
    ),
}


class OutputAgent:
    name = "OutputGuard"
    description = "Scans outgoing content for PII and sensitive data leakage"

    def analyze(self, text: str) -> AgentResult:
        detected = []
        for name, (pattern, _) in SENSITIVE_PATTERNS.items():
            if re.search(pattern, text):
                detected.append(f"Sensitive data detected: {name}")

        risk_score = min(len(detected) * 0.25, 1.0)
        if risk_score >= 0.70:
            decision = "block"
        elif risk_score >= 0.30:
            decision = "sanitize"
        else:
            decision = "allow"

        return AgentResult(
            agent_name=self.name,
            status="triggered" if detected else "active",
            decision=decision,
            confidence=0.92 if detected else 0.80,
            detected_patterns=detected,
        )

    def sanitize(self, text: str) -> str:
        for _, (pattern, replacement) in SENSITIVE_PATTERNS.items():
            text = re.sub(pattern, replacement, text)
        return text

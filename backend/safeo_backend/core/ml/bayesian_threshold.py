"""
Bayesian threshold adaptation engine for SafeO's 3-tier ML classifier.

Maintains Beta(alpha, beta) distributions over the optimal BLOCK threshold.
Updates from human feedback; exposes a dynamic block threshold used at scan time.

Primary path is deterministic Python math (temperature=0 equivalent).
Optional Fireworks LLM (llama-v3p1-8b-instruct) generates the one-sentence
reasoning field when SAFEO_ENABLE_BAYESIAN_LLM=true.
"""
from __future__ import annotations

import json
import logging
import sqlite3
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger("safeo.bayesian_threshold")

# ── System prompt (spec for LLM reasoning path) ───────────────────────────────

BAYESIAN_SYSTEM_PROMPT = """You are a Bayesian threshold adaptation engine for a cybersecurity inference system called SafeO.

Your job is to maintain and update an optimal BLOCK threshold for a 3-tier ML security classifier that scores inputs from 0.0 to 1.0, where scores >= threshold trigger a BLOCK decision.

## Your state
You maintain a Beta distribution Beta(alpha, beta) representing uncertainty over the optimal threshold.
- alpha: count of confirmed true positives (human said BLOCK was correct)
- beta: count of confirmed false positives (human said BLOCK was wrong)
- Current threshold = alpha / (alpha + beta)
- Starting prior: alpha=4, beta=2 (slight bias toward blocking — safer default for security)

## On each feedback event, you receive:
{
  "scan_id": "string",
  "original_score": float,
  "original_decision": "BLOCK" | "WARN" | "ALLOW",
  "human_verdict": "correct" | "false_positive" | "false_negative",
  "attack_class": "sqli" | "xss" | "prompt_injection" | "arabizi" | "arabic_injection" | "other",
  "tier_used": 1 | 2 | 3
}

## Update rules
- human_verdict = "correct" AND original_decision = "BLOCK" → alpha += 1
- human_verdict = "false_positive" → beta += 1
- human_verdict = "false_negative" AND original_decision = "ALLOW" → alpha += 2
- human_verdict = "correct" AND original_decision = "ALLOW" → no update

## Per-class tracking
Maintain SEPARATE Beta distributions per attack_class. The global threshold is the weighted average across classes by frequency. When a class has fewer than 10 samples, use the global threshold as prior for that class.

## Output format — respond ONLY with valid JSON, no explanation, no markdown:
{
  "updated_alpha": float,
  "updated_beta": float,
  "new_threshold": float,
  "threshold_95_low": float,
  "threshold_95_high": float,
  "confidence": "low" | "medium" | "high",
  "recommendation": "lower_threshold" | "raise_threshold" | "stable",
  "class_thresholds": {
    "sqli": float,
    "xss": float,
    "prompt_injection": float,
    "arabizi": float,
    "arabic_injection": float,
    "other": float
  },
  "drift_alert": boolean,
  "reasoning": "one sentence, plain English, max 20 words"
}

## Hard constraints
- Threshold must never go below 0.45 (safety floor)
- Threshold must never go above 0.90 (usability ceiling)
- If drift_alert is true, flag it but still apply the update
- Never return null fields — use current values if update has no effect
"""

ATTACK_CLASSES = (
    "sqli",
    "xss",
    "prompt_injection",
    "arabizi",
    "arabic_injection",
    "other",
)

PRIOR_ALPHA = 4.0
PRIOR_BETA = 2.0
THRESHOLD_FLOOR = 0.45
THRESHOLD_CEILING = 0.90
WARN_THRESHOLD = 0.30
MIN_CLASS_SAMPLES = 10
DRIFT_WINDOW = 10
DRIFT_DELTA = 0.05

# In-memory drift tracking (last N global thresholds after updates)
_threshold_history: Deque[float] = deque(maxlen=DRIFT_WINDOW)
_last_update_result: Optional[Dict[str, Any]] = None


def _db_path() -> Path:
    from ...utils.feedback_db import feedback_db_path

    return feedback_db_path()


def infer_attack_class(
    matched_patterns: List[str],
    script_detected: str = "latin",
) -> str:
    """Map scan patterns / script to Bayesian attack_class."""
    raw = " ".join(matched_patterns).lower()
    if "sql_injection" in raw or "sqli" in raw:
        return "sqli"
    if "xss" in raw:
        return "xss"
    if "prompt_injection" in raw:
        return "prompt_injection"
    if "idn_homograph" in raw or "homograph" in raw:
        return "idn_homograph"
    if script_detected == "arabizi" or "arabizi" in raw:
        return "arabizi"
    if script_detected in ("arabic", "urdu", "mixed") or "multilingual_evasion" in raw:
        return "arabic_injection"
    return "other"


def _clamp_threshold(value: float) -> float:
    return round(max(THRESHOLD_FLOOR, min(THRESHOLD_CEILING, value)), 4)


def _posterior_mean(alpha: float, beta: float) -> float:
    return _clamp_threshold(alpha / (alpha + beta))


def _credible_interval(alpha: float, beta: float) -> Tuple[float, float]:
    try:
        from scipy.stats import beta as beta_dist
        lo = float(beta_dist.ppf(0.025, alpha, beta))
        hi = float(beta_dist.ppf(0.975, alpha, beta))
    except Exception:
        mean = alpha / (alpha + beta)
        spread = 0.08
        lo, hi = mean - spread, mean + spread
    return _clamp_threshold(lo), _clamp_threshold(hi)


def _confidence_level(total_samples: int) -> str:
    if total_samples < 20:
        return "low"
    if total_samples <= 100:
        return "medium"
    return "high"


def _recommendation(prev_threshold: float, new_threshold: float) -> str:
    delta = new_threshold - prev_threshold
    if abs(delta) < 0.01:
        return "stable"
    return "raise_threshold" if delta > 0 else "lower_threshold"


def _rule_reasoning(
    human_verdict: str,
    original_decision: str,
    new_threshold: float,
    prev_threshold: float,
    drift_alert: bool,
) -> str:
    if human_verdict == "false_positive":
        return f"False positive recorded; threshold lowered to {new_threshold:.2f}."
    if human_verdict == "false_negative":
        return f"Missed attack; threshold raised to {new_threshold:.2f}."
    if human_verdict == "correct" and original_decision == "BLOCK":
        return f"Block confirmed correct; threshold stable at {new_threshold:.2f}."
    if drift_alert:
        return f"Threshold drift detected; now {new_threshold:.2f}."
    if abs(new_threshold - prev_threshold) < 0.01:
        return f"Threshold unchanged at {new_threshold:.2f}."
    direction = "raised" if new_threshold > prev_threshold else "lowered"
    return f"Threshold {direction} to {new_threshold:.2f} from feedback."


@dataclass
class BetaState:
    alpha: float = PRIOR_ALPHA
    beta: float = PRIOR_BETA
    sample_count: int = 0

    @property
    def threshold(self) -> float:
        return _posterior_mean(self.alpha, self.beta)

    def apply_update(self, human_verdict: str, original_decision: str) -> bool:
        """Return True if state was updated."""
        decision = (original_decision or "").upper()
        verdict = (human_verdict or "").lower()

        if verdict == "correct" and decision == "BLOCK":
            self.alpha += 1
            self.sample_count += 1
            return True
        if verdict == "false_positive":
            self.beta += 1
            self.sample_count += 1
            return True
        if verdict == "false_negative" and decision == "ALLOW":
            self.alpha += 2
            self.sample_count += 1
            return True
        return False


class BayesianThresholdEngine:
    """SQLite-backed Beta distributions for global + per-class thresholds."""

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._path = db_path or _db_path()
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self._path))
        conn.row_factory = sqlite3.Row
        return conn

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS bayesian_threshold (
                  scope TEXT PRIMARY KEY,
                  alpha REAL NOT NULL,
                  beta REAL NOT NULL,
                  sample_count INTEGER NOT NULL DEFAULT 0,
                  updated_at TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS bayesian_threshold_log (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  scan_id TEXT,
                  payload_json TEXT,
                  result_json TEXT,
                  timestamp TEXT
                )
            """)
            for scope in ("global",) + ATTACK_CLASSES:
                row = conn.execute(
                    "SELECT scope FROM bayesian_threshold WHERE scope = ?", (scope,)
                ).fetchone()
                if not row:
                    conn.execute(
                        """INSERT INTO bayesian_threshold
                           (scope, alpha, beta, sample_count, updated_at)
                           VALUES (?, ?, ?, 0, ?)""",
                        (scope, PRIOR_ALPHA, PRIOR_BETA, datetime.now(timezone.utc).isoformat()),
                    )
            conn.commit()

    def _load_state(self, scope: str) -> BetaState:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT alpha, beta, sample_count FROM bayesian_threshold WHERE scope = ?",
                (scope,),
            ).fetchone()
        if not row:
            return BetaState()
        return BetaState(
            alpha=float(row["alpha"]),
            beta=float(row["beta"]),
            sample_count=int(row["sample_count"]),
        )

    def _save_state(self, scope: str, state: BetaState) -> None:
        with self._connect() as conn:
            conn.execute(
                """UPDATE bayesian_threshold
                   SET alpha = ?, beta = ?, sample_count = ?, updated_at = ?
                   WHERE scope = ?""",
                (
                    state.alpha,
                    state.beta,
                    state.sample_count,
                    datetime.now(timezone.utc).isoformat(),
                    scope,
                ),
            )
            conn.commit()

    def get_global_state(self) -> BetaState:
        return self._load_state("global")

    def get_block_threshold(self, attack_class: Optional[str] = None) -> float:
        """Return effective BLOCK threshold (class-specific or global fallback)."""
        global_state = self._load_state("global")
        global_threshold = global_state.threshold

        if not attack_class or attack_class not in ATTACK_CLASSES:
            return global_threshold

        class_state = self._load_state(attack_class)
        if class_state.sample_count < MIN_CLASS_SAMPLES:
            return global_threshold
        return class_state.threshold

    def get_class_thresholds(self) -> Dict[str, float]:
        global_threshold = self._load_state("global").threshold
        out: Dict[str, float] = {}
        for cls in ATTACK_CLASSES:
            state = self._load_state(cls)
            if state.sample_count < MIN_CLASS_SAMPLES:
                out[cls] = global_threshold
            else:
                out[cls] = state.threshold
        return out

    def get_weighted_global_threshold(self) -> float:
        """Weighted average of class thresholds by sample count."""
        states = {cls: self._load_state(cls) for cls in ATTACK_CLASSES}
        total_weight = sum(s.sample_count for s in states.values())
        if total_weight == 0:
            return self._load_state("global").threshold

        weighted = sum(states[c].threshold * states[c].sample_count for c in ATTACK_CLASSES)
        return _clamp_threshold(weighted / total_weight)

    def process_feedback(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply Bayesian update from a feedback event and return structured result.
        """
        global _last_update_result

        scan_id = event.get("scan_id", "")
        human_verdict = event.get("human_verdict", "")
        original_decision = event.get("original_decision", "")
        attack_class = event.get("attack_class", "other")
        if attack_class not in ATTACK_CLASSES:
            attack_class = "other"

        global_state = self._load_state("global")
        class_state = self._load_state(attack_class)
        prev_threshold = global_state.threshold

        updated_global = global_state.apply_update(human_verdict, original_decision)
        updated_class = class_state.apply_update(human_verdict, original_decision)

        if updated_global:
            self._save_state("global", global_state)
        if updated_class:
            self._save_state(attack_class, class_state)

        new_threshold = self.get_weighted_global_threshold()
        if updated_global:
            _threshold_history.append(new_threshold)

        drift_alert = False
        if len(_threshold_history) >= 2:
            oldest = _threshold_history[0]
            if abs(new_threshold - oldest) > DRIFT_DELTA:
                drift_alert = True

        lo, hi = _credible_interval(global_state.alpha, global_state.beta)
        total_samples = int(global_state.alpha + global_state.beta - PRIOR_ALPHA - PRIOR_BETA)
        total_samples = max(0, total_samples)

        result: Dict[str, Any] = {
            "updated_alpha": round(global_state.alpha, 4),
            "updated_beta": round(global_state.beta, 4),
            "new_threshold": new_threshold,
            "threshold_95_low": lo,
            "threshold_95_high": hi,
            "confidence": _confidence_level(total_samples),
            "recommendation": _recommendation(prev_threshold, new_threshold),
            "class_thresholds": self.get_class_thresholds(),
            "drift_alert": drift_alert,
            "reasoning": _rule_reasoning(
                human_verdict, original_decision, new_threshold, prev_threshold, drift_alert
            ),
        }

        # Optional Fireworks LLM for reasoning only (deterministic math above)
        llm_reasoning = self._llm_reasoning(event, result)
        if llm_reasoning:
            result["reasoning"] = llm_reasoning

        with self._connect() as conn:
            conn.execute(
                """INSERT INTO bayesian_threshold_log
                   (scan_id, payload_json, result_json, timestamp)
                   VALUES (?, ?, ?, ?)""",
                (
                    scan_id,
                    json.dumps(event),
                    json.dumps(result),
                    datetime.now(timezone.utc).isoformat(),
                ),
            )
            conn.commit()

        _last_update_result = result
        logger.info(
            "bayesian threshold update scan_id=%s threshold=%.3f verdict=%s",
            scan_id, new_threshold, human_verdict,
        )
        return result

    @staticmethod
    def _llm_reasoning(event: Dict[str, Any], computed: Dict[str, Any]) -> Optional[str]:
        """Optional one-sentence reasoning via Fireworks llama-v3p1-8b-instruct."""
        from ...config.amd_config import ENABLE_BAYESIAN_LLM, BAYESIAN_LLM_MODEL, FIREWORKS_API_KEY

        if not ENABLE_BAYESIAN_LLM or not FIREWORKS_API_KEY:
            return None
        try:
            from openai import OpenAI
            from ...config.amd_config import FIREWORKS_BASE_URL

            client = OpenAI(base_url=FIREWORKS_BASE_URL, api_key=FIREWORKS_API_KEY)
            user = json.dumps({**event, "computed_state": computed})
            resp = client.chat.completions.create(
                model=BAYESIAN_LLM_MODEL,
                temperature=0.0,
                messages=[
                    {"role": "system", "content": BAYESIAN_SYSTEM_PROMPT},
                    {"role": "user", "content": user},
                ],
                response_format={"type": "json_object"},
                timeout=6,
            )
            raw = resp.choices[0].message.content or "{}"
            parsed = json.loads(raw)
            reasoning = parsed.get("reasoning")
            if isinstance(reasoning, str) and reasoning.strip():
                return reasoning.strip()[:120]
        except Exception as exc:
            logger.debug("Bayesian LLM reasoning skipped: %s", exc)
        return None

    def status(self) -> Dict[str, Any]:
        global_state = self._load_state("global")
        lo, hi = _credible_interval(global_state.alpha, global_state.beta)
        total_samples = max(0, int(global_state.alpha + global_state.beta - PRIOR_ALPHA - PRIOR_BETA))
        return {
            "updated_alpha": round(global_state.alpha, 4),
            "updated_beta": round(global_state.beta, 4),
            "new_threshold": self.get_weighted_global_threshold(),
            "block_threshold": self.get_block_threshold(),
            "warn_threshold": WARN_THRESHOLD,
            "threshold_95_low": lo,
            "threshold_95_high": hi,
            "confidence": _confidence_level(total_samples),
            "class_thresholds": self.get_class_thresholds(),
            "drift_alert": (
                len(_threshold_history) >= 2
                and abs(_threshold_history[-1] - _threshold_history[0]) > DRIFT_DELTA
            ),
            "last_update": _last_update_result,
            "threshold_floor": THRESHOLD_FLOOR,
            "threshold_ceiling": THRESHOLD_CEILING,
        }


_engine: Optional[BayesianThresholdEngine] = None


def get_bayesian_engine() -> BayesianThresholdEngine:
    global _engine
    if _engine is None:
        _engine = BayesianThresholdEngine()
    return _engine


def decision_label(
    score: float,
    attack_class: Optional[str] = None,
    block_threshold: Optional[float] = None,
    warn_threshold: float = WARN_THRESHOLD,
) -> str:
    """Map risk score to BLOCK / WARN / ALLOW using adaptive threshold."""
    block = block_threshold if block_threshold is not None else get_bayesian_engine().get_block_threshold(attack_class)
    if score >= block:
        return "BLOCK"
    if score >= warn_threshold:
        return "WARN"
    return "ALLOW"

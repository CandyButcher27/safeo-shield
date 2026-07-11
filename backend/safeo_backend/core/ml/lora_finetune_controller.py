"""
LoRA fine-tuning controller for SafeO Tier 2.

This module decides when to trigger fine-tuning, how to sample feedback data,
which LoRA hyperparameters to use, and whether an evaluated checkpoint is safe
to deploy. It does not train inside the API process; it returns deterministic
plans for a daily scheduler or worker.
"""
from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .bayesian_threshold import infer_attack_class
from .retraining_loop import get_feedback_store

logger = logging.getLogger("safeo.lora_controller")

ATTACK_CLASSES = (
    "sqli",
    "xss",
    "prompt_injection",
    "arabizi",
    "arabic_injection",
    "other",
)

BASE_MODEL = "distilbert"
DEFAULT_CURRENT_MODEL = {
    "version": "distilbert-safeo-v1",
    "checkpoint_hash": "0" * 64,
    "f1_score": 0.0,
    "false_positive_rate": 0.0,
    "false_negative_rate": 0.0,
    "deployed_at": "",
}

_last_decision: Optional[Dict[str, Any]] = None
_failed_checkpoint_log: List[Dict[str, Any]] = []
_fn_weight_boost = 0.0


def _empty_breakdown() -> Dict[str, Dict[str, int]]:
    return {cls: {"fp": 0, "fn": 0, "tp": 0} for cls in ATTACK_CLASSES}


def build_feedback_summary(limit: int = 1000) -> Dict[str, Any]:
    """Summarize labelled feedback for scheduler-driven LoRA decisions."""
    store = get_feedback_store()
    rows = store.get_recent(limit)
    breakdown = _empty_breakdown()
    fp = fn = tp = 0

    for row in rows:
        verdict = row.get("human_verdict")
        patterns_raw = row.get("matched_patterns") or ""
        patterns = [p.strip() for p in patterns_raw.split(",") if p.strip()]
        cls = infer_attack_class(patterns)
        if verdict == "false_positive":
            fp += 1
            breakdown[cls]["fp"] += 1
        elif verdict == "false_negative":
            fn += 1
            breakdown[cls]["fn"] += 1
        elif verdict == "correct" and (row.get("final_decision") or "").upper() == "BLOCK":
            tp += 1
            breakdown[cls]["tp"] += 1

    return {
        "total_samples_since_last_finetune": fp + fn + tp,
        "false_positives": fp,
        "false_negatives": fn,
        "confirmed_true_positives": tp,
        "class_breakdown": breakdown,
    }


def _rates(summary: Dict[str, Any]) -> Tuple[float, float]:
    total = int(summary.get("total_samples_since_last_finetune") or 0)
    if total <= 0:
        return 0.0, 0.0
    fp_rate = float(summary.get("false_positives", 0)) / total
    fn_rate = float(summary.get("false_negatives", 0)) / total
    return round(fp_rate, 4), round(fn_rate, 4)


def _degraded_class(summary: Dict[str, Any]) -> Optional[str]:
    breakdown = summary.get("class_breakdown") or {}
    for cls, counts in breakdown.items():
        if int(counts.get("fp", 0)) + int(counts.get("fn", 0)) >= 20:
            return cls
    return None


def _lora_config(buffer_size: int) -> Dict[str, Any]:
    if buffer_size < 200:
        r, alpha, epochs, lr = 4, 8, 2, 2e-4
    elif buffer_size <= 500:
        r, alpha, epochs, lr = 8, 16, 3, 2e-4
    else:
        r, alpha, epochs, lr = 16, 32, 4, 1e-4

    return {
        "r": r,
        "lora_alpha": alpha,
        "epochs": epochs,
        "lr": lr,
        "target_modules": ["attention.self.query", "attention.self.value"],
        "lora_dropout": 0.1,
        "bias": "none",
        "task_type": "SEQ_CLS",
        "per_device_train_batch_size": 16,
        "warmup_steps": 10,
        "weight_decay": 0.01,
        "fp16": False,
        "bf16": True,
    }


def _next_version(current_version: str) -> str:
    match = re.search(r"-v(\d+)$", current_version or "")
    n = int(match.group(1)) if match else 1
    return f"{BASE_MODEL}-safeo-v{n + 1}"


def _checkpoint_hash(
    *,
    current_hash: str,
    new_version: str,
    training_data_hashes: List[str],
    timestamp: str,
) -> str:
    payload = json.dumps({
        "new_version": new_version,
        "prev_checkpoint_hash": current_hash,
        "training_data_hashes": training_data_hashes,
        "timestamp": timestamp,
    }, sort_keys=True)
    return hashlib.sha256(payload.encode()).hexdigest()


def _sampling() -> Dict[str, Any]:
    return {
        "fp_weight": 2.0,
        "fn_weight": 3.0 + _fn_weight_boost,
        "tp_weight": 1.0,
        "max_samples": 1000,
        "eval_split": 0.2,
    }


def _base_response(
    *,
    should_finetune: bool,
    reason: str,
    lora_config: Optional[Dict[str, Any]],
    data_sampling: Optional[Dict[str, Any]],
    evaluation_gate: Optional[Dict[str, Any]],
    new_model_version: Optional[str],
    deploy: bool,
    checkpoint_hash: Optional[str],
    prev_checkpoint_hash: Optional[str],
    alert: Optional[str],
) -> Dict[str, Any]:
    return {
        "should_finetune": should_finetune,
        "reason": reason[:140],
        "lora_config": lora_config,
        "data_sampling": data_sampling,
        "evaluation_gate": evaluation_gate,
        "new_model_version": new_model_version,
        "deploy": deploy,
        "checkpoint_hash": checkpoint_hash,
        "prev_checkpoint_hash": prev_checkpoint_hash,
        "alert": alert,
    }


def decide_lora_finetune(payload: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decide whether to fine-tune and optionally gate an evaluated checkpoint.

    Expected payload follows the prompt schema. Optional fields:
      - new_model_metrics: {f1_score, false_negative_rate, training_data_hashes}
    """
    global _last_decision, _fn_weight_boost

    summary = payload.get("feedback_summary") or build_feedback_summary()
    current = payload.get("current_model") or DEFAULT_CURRENT_MODEL
    gpu_available = bool(payload.get("gpu_available", False))
    buffer_size = int(payload.get("buffer_size") or summary.get("total_samples_since_last_finetune") or 0)

    fp_rate, fn_rate = _rates(summary)
    degraded_cls = _degraded_class(summary)
    total = int(summary.get("total_samples_since_last_finetune") or 0)

    if not gpu_available:
        result = _base_response(
            should_finetune=False,
            reason="AMD GPU unavailable — deferring fine-tune",
            lora_config=None,
            data_sampling=None,
            evaluation_gate=None,
            new_model_version=None,
            deploy=False,
            checkpoint_hash=None,
            prev_checkpoint_hash=None,
            alert=None,
        )
        _last_decision = result
        return result

    if total < 50:
        result = _base_response(
            should_finetune=False,
            reason="Fewer than 50 new labelled samples; deferring fine-tune.",
            lora_config=None,
            data_sampling=None,
            evaluation_gate=None,
            new_model_version=None,
            deploy=False,
            checkpoint_hash=None,
            prev_checkpoint_hash=None,
            alert=None,
        )
        _last_decision = result
        return result

    if fp_rate <= 0.12 and fn_rate <= 0.05 and degraded_cls is None:
        result = _base_response(
            should_finetune=False,
            reason="Feedback rates are within tolerance; no fine-tune needed.",
            lora_config=None,
            data_sampling=None,
            evaluation_gate=None,
            new_model_version=None,
            deploy=False,
            checkpoint_hash=None,
            prev_checkpoint_hash=None,
            alert=None,
        )
        _last_decision = result
        return result

    new_version = _next_version(str(current.get("version", DEFAULT_CURRENT_MODEL["version"])))
    current_f1 = float(current.get("f1_score", 0.0))
    current_fn_rate = float(current.get("false_negative_rate", fn_rate))
    gate = {
        "min_f1": round(current_f1 - 0.01, 4),
        "max_fn_rate": current_fn_rate,
    }

    new_metrics = payload.get("new_model_metrics")
    if not new_metrics:
        result = _base_response(
            should_finetune=True,
            reason="Triggering LoRA fine-tune from accumulated feedback degradation.",
            lora_config=_lora_config(buffer_size),
            data_sampling=_sampling(),
            evaluation_gate=gate,
            new_model_version=new_version,
            deploy=False,
            checkpoint_hash=None,
            prev_checkpoint_hash=current.get("checkpoint_hash"),
            alert=None,
        )
        _last_decision = result
        return result

    new_f1 = float(new_metrics.get("f1_score", 0.0))
    new_fn_rate = float(new_metrics.get("false_negative_rate", 1.0))
    alert = None
    if new_fn_rate > current_fn_rate:
        alert = "URGENT: false negative rate increased; checkpoint blocked from deployment."

    deploy = new_f1 >= gate["min_f1"] and new_fn_rate <= gate["max_fn_rate"]
    timestamp = datetime.now(timezone.utc).isoformat()
    checkpoint = None
    if deploy:
        checkpoint = _checkpoint_hash(
            current_hash=str(current.get("checkpoint_hash", "")),
            new_version=new_version,
            training_data_hashes=list(new_metrics.get("training_data_hashes") or []),
            timestamp=timestamp,
        )
        reason = "Evaluation gate passed; deploying new LoRA checkpoint."
    else:
        _fn_weight_boost += 0.5
        reason = "Evaluation gate failed; checkpoint logged and deployment blocked."
        _failed_checkpoint_log.append({
            "version": new_version,
            "timestamp": timestamp,
            "new_f1": new_f1,
            "new_fn_rate": new_fn_rate,
            "reason": reason,
            "alert": alert,
        })

    result = _base_response(
        should_finetune=True,
        reason=reason,
        lora_config=_lora_config(buffer_size),
        data_sampling=_sampling(),
        evaluation_gate=gate,
        new_model_version=new_version,
        deploy=deploy,
        checkpoint_hash=checkpoint,
        prev_checkpoint_hash=current.get("checkpoint_hash"),
        alert=alert,
    )
    _last_decision = result
    return result


def get_lora_controller_status() -> Dict[str, Any]:
    return {
        "last_decision": _last_decision,
        "failed_checkpoints": _failed_checkpoint_log[-10:],
        "fn_weight_boost": _fn_weight_boost,
        "feedback_summary": build_feedback_summary(),
    }

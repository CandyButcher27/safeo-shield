"""
Population Stability Index (PSI) drift detector.

Maintains a rolling window of 500 payload feature vectors and compares the
current distribution to the baseline (first 200 requests) using PSI.

PSI > 0.2 on any feature → drift_detected = True.
"""
from __future__ import annotations

import logging
from collections import deque
from datetime import datetime, timezone
from typing import Any, Deque, Dict, List, Optional

import math

logger = logging.getLogger("safeo.drift")

# Feature indices
# [script_type_encoded, entropy_value, attack_category_encoded, payload_length_bucket, hour_of_day]
_SCRIPT_MAP = {"latin": 0, "arabic": 1, "urdu": 2, "arabizi": 3, "mixed": 4}
_ATTACK_MAP  = {"none": 0, "sql_injection": 1, "xss": 2, "prompt_injection": 3,
                "command_injection": 4, "path_traversal": 5, "other": 6}

WINDOW_SIZE   = 500
BASELINE_SIZE = 200
PSI_THRESHOLD = 0.2
_BINS = 10  # buckets per continuous feature


def _length_bucket(length: int) -> int:
    if length < 20:    return 0
    if length < 50:    return 1
    if length < 100:   return 2
    if length < 200:   return 3
    if length < 500:   return 4
    return 5


def _psi_1d(baseline: List[float], current: List[float], n_bins: int = 10) -> float:
    """PSI for one continuous feature dimension."""
    if not baseline or not current:
        return 0.0
    lo = min(min(baseline), min(current))
    hi = max(max(baseline), max(current))
    if hi == lo:
        return 0.0
    edges = [lo + (hi - lo) * i / n_bins for i in range(n_bins + 1)]

    def _hist(vals: List[float]) -> List[float]:
        counts = [0] * n_bins
        for v in vals:
            idx = int((v - lo) / (hi - lo) * n_bins)
            idx = min(idx, n_bins - 1)
            counts[idx] += 1
        n = len(vals)
        return [max(c / n, 1e-6) for c in counts]

    base_hist = _hist(baseline)
    curr_hist = _hist(current)
    psi = sum(
        (curr_hist[i] - base_hist[i]) * math.log(curr_hist[i] / base_hist[i])
        for i in range(n_bins)
    )
    return abs(psi)


class DriftDetector:
    def __init__(self) -> None:
        self._window: Deque[List[float]] = deque(maxlen=WINDOW_SIZE)
        self._baseline: List[List[float]] = []
        self._alerts: Deque[Dict[str, Any]] = deque(maxlen=50)
        self._baseline_locked = False

    def update(self, features: List[float]) -> None:
        self._window.append(features)
        if not self._baseline_locked and len(self._window) >= BASELINE_SIZE:
            self._baseline = list(self._window)
            self._baseline_locked = True
            logger.info("DriftDetector: baseline locked (%d samples)", len(self._baseline))
        if self._baseline_locked and len(self._window) % 50 == 0:
            self._check_drift()

    def _check_drift(self) -> None:
        if not self._baseline:
            return
        n_feat = len(self._baseline[0])
        psi_scores: Dict[str, float] = {}
        names = ["script_type", "entropy", "attack_category", "length_bucket", "hour_of_day"]
        drift_detected = False
        for i in range(n_feat):
            base_col = [row[i] for row in self._baseline]
            curr_col = [row[i] for row in self._window]
            psi = _psi_1d(base_col, curr_col)
            label = names[i] if i < len(names) else f"feat_{i}"
            psi_scores[label] = round(psi, 4)
            if psi > PSI_THRESHOLD:
                drift_detected = True
        if drift_detected:
            alert = {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "psi_scores": psi_scores,
                "window_size": len(self._window),
            }
            self._alerts.append(alert)
            logger.warning("DriftDetector: DRIFT DETECTED psi=%s", psi_scores)

    def status(self) -> Dict[str, Any]:
        if not self._baseline or not self._window:
            return {
                "drift_detected": False,
                "psi_scores": {},
                "alert_count": 0,
                "last_alert": None,
                "baseline_size": len(self._baseline),
            }
        n_feat = len(self._baseline[0])
        names = ["script_type", "entropy", "attack_category", "length_bucket", "hour_of_day"]
        psi_scores: Dict[str, float] = {}
        drift_detected = False
        for i in range(n_feat):
            base_col = [row[i] for row in self._baseline]
            curr_col = [row[i] for row in self._window]
            psi = _psi_1d(base_col, curr_col)
            label = names[i] if i < len(names) else f"feat_{i}"
            psi_scores[label] = round(psi, 4)
            if psi > PSI_THRESHOLD:
                drift_detected = True
        return {
            "drift_detected": drift_detected,
            "psi_scores": psi_scores,
            "alert_count": len(self._alerts),
            "last_alert": self._alerts[-1]["timestamp"] if self._alerts else None,
            "baseline_size": len(self._baseline),
        }


def make_feature_vector(
    script: str, entropy: float, attack_categories: List[str],
    payload_len: int, hour: int,
) -> List[float]:
    script_enc = float(_SCRIPT_MAP.get(script, 0))
    attack_enc = float(_ATTACK_MAP.get(
        attack_categories[0] if attack_categories else "none", 0
    ))
    return [
        script_enc,
        float(entropy),
        attack_enc,
        float(_length_bucket(payload_len)),
        float(hour % 24),
    ]


_detector = DriftDetector()


def get_drift_detector() -> DriftDetector:
    return _detector

"""
Active retraining loop — improves tier-1 keyword weights and tier-2 TF-IDF fallback
from human feedback stored in SQLite (safeo_feedback.db).
"""
from __future__ import annotations

import logging
import os
import re
import sqlite3
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple

logger = logging.getLogger("safeo.retraining")

# DB at SafeO repo root (parent of backend/)
_DB_PATH = Path(__file__).resolve().parents[4] / "safeo_feedback.db"
_FEEDBACK_TRIGGER = 50
_TIER2_BUFFER_TRIGGER = 100

_retraining_log: Deque[Dict[str, Any]] = deque(maxlen=100)
_tier2_extra_buffer: List[Tuple[str, int]] = []
_feedback_since_retrain = 0


def _db_path() -> Path:
    from ...utils.feedback_db import feedback_db_path

    return feedback_db_path()


class FeedbackStore:
  """SQLite-backed store for human verdicts on scan results."""

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
        CREATE TABLE IF NOT EXISTS feedback (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          scan_id TEXT,
          original_input TEXT,
          normalised_input TEXT,
          tier1_score REAL,
          tier2_score REAL,
          llm_score REAL,
          final_decision TEXT,
          human_verdict TEXT,
          reviewer TEXT,
          timestamp TEXT,
          matched_patterns TEXT
        )
      """)
      conn.commit()

  def record(
    self,
    scan_result: Dict[str, Any],
    human_verdict: str,
    reviewer: str,
  ) -> int:
    """Insert a feedback row. Returns row id. Triggers Bayesian threshold update."""
    ts = datetime.now(timezone.utc).isoformat()
    patterns_raw = scan_result.get("matched_patterns") or []
    if isinstance(patterns_raw, str):
      patterns = [p.strip() for p in patterns_raw.split(",") if p.strip()]
    else:
      patterns = list(patterns_raw)
    patterns_str = ",".join(patterns)
    with self._connect() as conn:
      cur = conn.execute(
        """INSERT INTO feedback
           (scan_id, original_input, normalised_input, tier1_score, tier2_score,
            llm_score, final_decision, human_verdict, reviewer, timestamp, matched_patterns)
           VALUES (?,?,?,?,?,?,?,?,?,?,?)""",
        (
          scan_result.get("scan_id", ""),
          scan_result.get("original_input", ""),
          scan_result.get("normalised_input", ""),
          float(scan_result.get("tier1_score", 0.0)),
          float(scan_result.get("tier2_score") or 0.0),
          float(scan_result.get("llm_score") or 0.0),
          scan_result.get("final_decision", ""),
          human_verdict,
          reviewer,
          ts,
          patterns_str,
        ),
      )
      conn.commit()
      row_id = cur.lastrowid

    from .bayesian_threshold import get_bayesian_engine, infer_attack_class
    attack_class = scan_result.get("attack_class") or infer_attack_class(
      patterns,
      scan_result.get("script_detected", "latin"),
    )
    get_bayesian_engine().process_feedback({
      "scan_id": scan_result.get("scan_id", ""),
      "original_score": float(
        scan_result.get("risk_score")
        or scan_result.get("tier1_score")
        or 0.0
      ),
      "original_decision": (scan_result.get("final_decision") or "ALLOW").upper(),
      "human_verdict": human_verdict,
      "attack_class": attack_class,
      "tier_used": int(scan_result.get("tier_used") or 1),
    })

    global _feedback_since_retrain
    if human_verdict in ("false_positive", "false_negative"):
      _feedback_since_retrain += 1
      if _feedback_since_retrain >= _FEEDBACK_TRIGGER:
        RetrainingScheduler().run()
        _feedback_since_retrain = 0

    return row_id

  def get_recent(self, n: int = 200) -> List[Dict[str, Any]]:
    with self._connect() as conn:
      rows = conn.execute(
        "SELECT * FROM feedback ORDER BY id DESC LIMIT ?", (n,)
      ).fetchall()
    return [dict(r) for r in rows]

  def get_errors(self) -> Dict[str, List[Dict[str, Any]]]:
    with self._connect() as conn:
      fps = conn.execute(
        "SELECT * FROM feedback WHERE human_verdict = 'false_positive' ORDER BY id DESC"
      ).fetchall()
      fns = conn.execute(
        "SELECT * FROM feedback WHERE human_verdict = 'false_negative' ORDER BY id DESC"
      ).fetchall()
    return {
      "false_positives": [dict(r) for r in fps],
      "false_negatives": [dict(r) for r in fns],
    }

  def count(self) -> int:
    with self._connect() as conn:
      row = conn.execute("SELECT COUNT(*) AS c FROM feedback").fetchone()
    return int(row["c"]) if row else 0

  def error_rates(self) -> Tuple[float, float]:
    with self._connect() as conn:
      total = conn.execute("SELECT COUNT(*) AS c FROM feedback").fetchone()["c"]
      if not total:
        return 0.0, 0.0
      fp = conn.execute(
        "SELECT COUNT(*) AS c FROM feedback WHERE human_verdict = 'false_positive'"
      ).fetchone()["c"]
      fn = conn.execute(
        "SELECT COUNT(*) AS c FROM feedback WHERE human_verdict = 'false_negative'"
      ).fetchone()["c"]
    return round(fp / total, 4), round(fn / total, 4)


class RetrainingScheduler:
  """Triggered every 50 new feedback records (count-based, not timer)."""

  def run(self) -> Dict[str, Any]:
    store = get_feedback_store()
    errors = store.get_errors()
    fps = errors["false_positives"]
    fns = errors["false_negatives"]
    recent = store.get_recent(200)

    weights_changed: Dict[str, float] = {}
    weights_changed.update(self._retrain_tier1(fps, fns))
    tier2_retrained = self._retrain_tier2(fps, fns)

    fp_rate, fn_rate = store.error_rates()
    event = {
      "timestamp": datetime.now(timezone.utc).isoformat(),
      "records_used": len(recent),
      "weights_changed": weights_changed,
      "tier2_retrained": tier2_retrained,
      "false_positive_rate": fp_rate,
      "false_negative_rate": fn_rate,
    }
    _retraining_log.append(event)
    logger.info("retraining complete: %s", event)
    return event

  def _retrain_tier1(
    self, fps: List[Dict], fns: List[Dict]
  ) -> Dict[str, float]:
    """Adjust CATEGORY_WEIGHTS in keyword_detector by ±10%."""
    from .keyword_detector import CATEGORY_WEIGHTS

    changed: Dict[str, float] = {}

    def _categories_from_row(row: Dict) -> List[str]:
      pats = (row.get("matched_patterns") or "").split(",")
      cats: List[str] = []
      for p in pats:
        p = p.strip()
        if not p:
          continue
        cat = p.split(":")[0].replace("decoded", "").strip()
        if cat and cat in CATEGORY_WEIGHTS:
          cats.append(cat)
      return list(set(cats))

    for row in fps:
      for cat in _categories_from_row(row):
        old = CATEGORY_WEIGHTS[cat]
        new = round(max(0.1, old * 0.90), 4)
        CATEGORY_WEIGHTS[cat] = new
        changed[cat] = new

    for row in fns:
      for cat in _categories_from_row(row):
        old = CATEGORY_WEIGHTS.get(cat, 0.5)
        new = round(min(1.0, old * 1.10), 4)
        CATEGORY_WEIGHTS[cat] = new
        changed[cat] = new

    return changed

  def _retrain_tier2(self, fps: List[Dict], fns: List[Dict]) -> bool:
    """Append labelled examples; retrain TF-IDF fallback when buffer hits 100."""
    global _tier2_extra_buffer

    for row in fps:
      text = row.get("normalised_input") or row.get("original_input") or ""
      if text:
        _tier2_extra_buffer.append((text, 0))

    for row in fns:
      text = row.get("normalised_input") or row.get("original_input") or ""
      if text:
        _tier2_extra_buffer.append((text, 1))

    if len(_tier2_extra_buffer) < _TIER2_BUFFER_TRIGGER:
      return False

    try:
      from sklearn.feature_extraction.text import TfidfVectorizer
      from sklearn.linear_model import LogisticRegression
      from .tier2_classifier import _TEXTS, _LABELS, get_tier2_classifier

      batch = _tier2_extra_buffer[:_TIER2_BUFFER_TRIGGER]
      _tier2_extra_buffer = _tier2_extra_buffer[_TIER2_BUFFER_TRIGGER:]

      all_texts = list(_TEXTS) + [t for t, _ in batch]
      all_labels = list(_LABELS) + [l for _, l in batch]

      vec = TfidfVectorizer(ngram_range=(1, 2), max_features=2000)
      X = vec.fit_transform(all_texts)
      clf = LogisticRegression(max_iter=500, C=1.0)
      clf.fit(X, all_labels)

      clf_instance = get_tier2_classifier()
      clf_instance._fallback_pipeline = (vec, clf)
      logger.info("tier2 TF-IDF fallback retrained on %d examples", len(all_texts))
      return True
    except Exception as exc:
      logger.warning("tier2 retrain failed: %s", exc)
      return False


_store: Optional[FeedbackStore] = None


def get_feedback_store() -> FeedbackStore:
  global _store
  if _store is None:
    _store = FeedbackStore()
  return _store


def get_retraining_log(limit: int = 20) -> List[Dict[str, Any]]:
  return list(_retraining_log)[-limit:]


def get_model_health() -> Dict[str, Any]:
  store = get_feedback_store()
  fp_rate, fn_rate = store.error_rates()
  log = list(_retraining_log)
  last_at = log[-1]["timestamp"] if log else None
  from ...utils.tier_stats import get_stats
  tier = get_stats()
  return {
    "false_positive_rate": fp_rate,
    "false_negative_rate": fn_rate,
    "retraining_count": len(log),
    "last_retrained_at": last_at,
    "feedback_total": store.count(),
    "llm_calls_saved_pct": tier.get("llm_savings_pct", 0.0),
  }

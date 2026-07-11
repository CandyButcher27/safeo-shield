"""Resolve a writable SQLite path for feedback and Bayesian threshold state."""
from __future__ import annotations

import logging
import os
from pathlib import Path

logger = logging.getLogger("safeo.feedback_db")

# Repo root: backend/safeo_backend/utils -> parents[3]
_DEFAULT_PATH = Path(__file__).resolve().parents[3] / "safeo_feedback.db"


def feedback_db_path() -> Path:
    """Return SAFEO_FEEDBACK_DB when writable, else repo-local safeo_feedback.db."""
    override = os.getenv("SAFEO_FEEDBACK_DB")
    if not override:
        _ensure_parent(_DEFAULT_PATH)
        return _DEFAULT_PATH

    candidate = Path(override)
    if _is_writable_dir(candidate.parent):
        _ensure_parent(candidate)
        return candidate

    logger.warning(
        "SAFEO_FEEDBACK_DB %s is not writable on this host; using %s",
        candidate,
        _DEFAULT_PATH,
    )
    _ensure_parent(_DEFAULT_PATH)
    return _DEFAULT_PATH


def _ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def _is_writable_dir(path: Path) -> bool:
    try:
        path.mkdir(parents=True, exist_ok=True)
        probe = path / ".safeo_write_probe"
        probe.write_text("", encoding="utf-8")
        probe.unlink(missing_ok=True)
        return True
    except OSError:
        return False

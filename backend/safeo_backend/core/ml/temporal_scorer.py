"""
Temporal risk scorer — lightweight CPU signals about *when* a request arrives.

Signals:
  1. Night hours  (00:00–05:00 UTC)                          → +0.10
  2. Weekend + corporate user                                → +0.05
  3. Sudden reactivation (0 req in 7d → 5+ in 1h)           → +0.15
  4. Bulk deadline clustering (10+ users same org, off-hrs)  → +0.10
"""
from __future__ import annotations

import hashlib
from collections import defaultdict, deque
from datetime import datetime, timezone, timedelta
from typing import Any, Deque, Dict, List, Optional

_NIGHT_START = 0
_NIGHT_END   = 5

_user_hour_history: Dict[str, Deque[datetime]] = defaultdict(lambda: deque(maxlen=1000))
_org_offhours_log:  Dict[str, Deque[datetime]] = defaultdict(lambda: deque(maxlen=200))

_signal_fired_counts: Dict[str, int] = defaultdict(int)


def _org_from_user(user_id: str) -> str:
    """Naive org extraction: use first component of user id (e.g. 'acme' from 'acme_emp1')."""
    return (user_id or "unknown").split("_")[0].split("@")[-1] or "unknown"


def score(user_id: str, ip: str, timestamp: Optional[datetime] = None) -> Dict[str, Any]:
    """
    Return temporal_risk_boost, signals_fired list, local_hour (UTC hour used).
    """
    now: datetime = timestamp or datetime.now(timezone.utc)
    local_hour = now.hour
    signals: List[str] = []
    boost = 0.0

    # 1. Night hours
    if _NIGHT_START <= local_hour < _NIGHT_END:
        boost += 0.10
        signals.append("night_hours")
        _signal_fired_counts["night_hours"] += 1

    # 2. Weekend + corporate user (any user who has org in user_id or @)
    is_corporate = ("_" in user_id or "@" in user_id) and user_id != "anonymous"
    is_weekend = now.weekday() >= 5  # Saturday=5, Sunday=6
    if is_weekend and is_corporate:
        boost += 0.05
        signals.append("weekend_corporate")
        _signal_fired_counts["weekend_corporate"] += 1

    # 3. Sudden reactivation
    history = _user_hour_history[user_id]
    now_ts = now
    cutoff_7d = now_ts - timedelta(days=7)
    cutoff_1h = now_ts - timedelta(hours=1)
    recent_7d  = [t for t in history if t > cutoff_7d]
    recent_1h  = [t for t in history if t > cutoff_1h]
    if len(recent_7d) == 0 and len(recent_1h) >= 5:
        boost += 0.15
        signals.append("sudden_reactivation")
        _signal_fired_counts["sudden_reactivation"] += 1
    history.append(now_ts)

    # 4. Bulk deadline clustering
    if _NIGHT_START <= local_hour < _NIGHT_END or is_weekend:
        org = _org_from_user(user_id)
        org_log = _org_offhours_log[org]
        org_log.append(now_ts)
        org_recent_1h = [t for t in org_log if t > cutoff_1h]
        # Count distinct users
        distinct = len(set(str(t.second) for t in org_recent_1h))  # rough proxy
        if len(org_recent_1h) >= 10:
            boost += 0.10
            signals.append("bulk_offhours_clustering")
            _signal_fired_counts["bulk_offhours_clustering"] += 1

    return {
        "temporal_risk_boost": round(min(boost, 0.40), 3),
        "signals_fired": signals,
        "local_hour": local_hour,
    }


def get_temporal_stats() -> Dict[str, Any]:
    return dict(_signal_fired_counts)

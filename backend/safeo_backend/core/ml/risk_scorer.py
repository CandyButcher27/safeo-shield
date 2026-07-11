"""
Risk scorer: evidence fusion via Dempster-Shafer Noisy-OR model.

Architecture (three independent evidence layers):
  1. Keyword / Regex layer  (k)  -- detect_threats() in keyword_detector.py
  2. Structural anomaly layer (s) -- information-theoretic signals in entropy.py
  3. N-gram similarity layer  (n) -- character trigram cosine similarity to attack corpus

Dempster-Shafer Noisy-OR combination:
  belief(threat) = 1 - ∏(1 - mᵢ)

This is mathematically superior to a linear weighted sum:
  • Bounded [0,1] without manual clamping.
  • Properly models independent evidence: two weak signals together become
    meaningfully stronger (e.g. no keyword match + high entropy + ngram hit).
  • Avoids double-counting correlated sources because they stay in separate layers.

Additional guardrails (preserved from original design):
  • Multi-category keyword co-occurrence boost (composite attack chains).
  • High-confidence keyword floor (known signatures cannot be diluted).
  • Decoded-payload re-scoring (iterative URL-decode before analysis).
"""

from urllib.parse import unquote, unquote_plus
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from ...agents.multilingual_agent import get_multilingual_agent
from .drift_detector import get_drift_detector, make_feature_vector
from .temporal_scorer import score as temporal_score
from .entropy import (
    shannon_entropy,
    character_distribution_anomaly,
    repetition_score,
    compression_anomaly,
    token_burst_score,
    bigram_markov_entropy,
    positional_concentration,
)
from .keyword_detector import detect_threats
from .url_scanner import url_risk_signal
from .ngram_similarity import ngram_attack_similarity


def _iterative_decode(text: str, rounds: int = 3) -> str:
    """URL-decode iteratively, handling both %XX and + (form encoding)."""
    decoded = text
    for _ in range(rounds):
        candidate = unquote_plus(decoded)
        if candidate == decoded:
            candidate = unquote(decoded)
        if candidate == decoded:
            break
        decoded = candidate
    return decoded


def _structural_signal(
    entropy_val: float,
    char_anomaly: float,
    repetition: float,
    compress: float,
    burst: float,
    bigram_entropy: float,
    pos_concentration: float,
) -> float:
    """
    Combine seven information-theoretic features into a single structural anomaly
    signal using a weighted mean. Each feature is already normalized to [0, 1].

    Weights reflect empirical discriminatory power:
      - char_anomaly and compression are most reliable for payload detection.
      - bigram_markov_entropy adds novel NLP-layer signal.
      - positional_concentration captures injection appended to legitimate text.
    """
    raw = (
        entropy_val         * 0.14
        + char_anomaly      * 0.22
        + repetition        * 0.13
        + compress          * 0.22
        + burst             * 0.18
        + bigram_entropy    * 0.07   # kept lower: English baseline bigram entropy is already ~0.4
        + pos_concentration * 0.04
    )
    # raw is already in [0, 1] since all inputs and weights sum to 1.0.
    return min(raw, 1.0)


def _ds_noisy_or(*beliefs: float) -> float:
    """
    Dempster-Shafer Noisy-OR evidence combination for binary frame {Threat, Uncertain}.

    For each evidence source i with mass m_i({Threat}):
      belief(Threat) = 1 - ∏(1 - m_i)

    Properties:
      - If any single source has m_i = 1.0, combined belief = 1.0 (certain threat).
      - If all sources have m_i = 0.0, combined belief = 0.0 (no evidence).
      - Two moderate signals (e.g. 0.4 + 0.4) → 1 - 0.6*0.6 = 0.64 (stronger than either alone).
    """
    product = 1.0
    for b in beliefs:
        product *= max(0.0, 1.0 - b)
    return round(1.0 - product, 4)


def calculate_risk_score(
    text: str,
    user_id: str = "anonymous",
    behavioural_risk: float = 0.0,
    timestamp: Optional[datetime] = None,
) -> Tuple[float, str, List[str], List[str], Dict[str, Any]]:
    """
    Fuse all ML evidence layers into a single 0-1 risk score.

    Returns:
        risk_score, decision, detected_patterns, explanation_parts, metadata
        metadata includes script_detected and evasion_suspected from MultilingualAgent.
    """
    meta: Dict[str, Any] = {
        "script_detected": "latin",
        "evasion_suspected": False,
        "evasion_confidence": 0.0,
    }
    if not text or not text.strip():
        return 0.0, "allow", [], ["Empty input — no risk detected"], meta

    ml_agent = get_multilingual_agent()
    ml_result = ml_agent.analyse(text)
    meta["script_detected"] = ml_result.get("script_detected", "latin")
    meta["evasion_suspected"] = bool(ml_result.get("evasion_suspected"))
    meta["evasion_confidence"] = float(ml_result.get("confidence", 0.0))

    scoring_text = ml_result.get("normalised") or text
    decoded_text = _iterative_decode(scoring_text)

    # ── Layer 1: Structural anomaly signals ──────────────────────────────────
    entropy_val      = shannon_entropy(scoring_text)
    char_anomaly     = character_distribution_anomaly(scoring_text)
    repetition       = repetition_score(scoring_text)
    compress         = compression_anomaly(scoring_text)
    burst            = token_burst_score(scoring_text)
    bigram_entropy   = bigram_markov_entropy(scoring_text)
    pos_conc         = positional_concentration(scoring_text)

    structural = _structural_signal(
        entropy_val, char_anomaly, repetition, compress,
        burst, bigram_entropy, pos_conc,
    )

    # ── Layer 2: Keyword / regex pattern matching ─────────────────────────────
    categories, keyword_score, patterns = detect_threats(scoring_text)

    # URL / IDN homograph layer (feeds Tier 1 when input is a link)
    url_signal, url_patterns, url_explanations, url_meta = url_risk_signal(text)
    if url_patterns:
        patterns.extend(url_patterns)
        categories = list(set(categories + ["idn_homograph"]))
        keyword_signal = max(keyword_score, url_signal)
        meta["url_analysis"] = url_meta
    else:
        keyword_signal = keyword_score

    # Re-run on URL-decoded form to catch obfuscated payloads.
    decoded_categories, decoded_keyword_score, decoded_patterns = detect_threats(decoded_text)
    if decoded_text != text and decoded_patterns:
        patterns.extend([f"decoded:{p}" for p in decoded_patterns])
        categories = list(set(categories + decoded_categories))
    keyword_signal = max(keyword_signal, decoded_keyword_score)

    # ── Layer 3: N-gram cosine similarity to attack corpus ───────────────────
    ngram_score, ngram_families = ngram_attack_similarity(scoring_text)
    # Also check decoded form; take the stronger signal.
    if decoded_text != scoring_text:
        decoded_ngram_score, _ = ngram_attack_similarity(decoded_text)
        ngram_score = max(ngram_score, decoded_ngram_score)

    evasion_signal = 0.0
    if meta["evasion_suspected"]:
        evasion_signal = min(0.55 + meta["evasion_confidence"] * 0.4, 0.95)
        patterns.append(f"multilingual_evasion:{ml_result.get('method', 'heuristic')}")

    # ── Temporal risk boost ───────────────────────────────────────────────────
    ts = timestamp or datetime.now(timezone.utc)
    temporal = temporal_score(user_id, "", ts)
    temporal_boost = temporal.get("temporal_risk_boost", 0.0)
    meta["temporal_signals"] = temporal.get("signals_fired", [])
    meta["temporal_boost"] = temporal_boost

    # ── Dempster-Shafer Noisy-OR fusion (core signals) ────────────────────────
    score = _ds_noisy_or(keyword_signal, structural, ngram_score, evasion_signal)

    # ── Behavioural risk addition (weight 0.15, other sources scale 0.85) ────
    beh_contribution = min(behavioural_risk, 1.0) * 0.15
    score = round(min(score * 0.85 + beh_contribution + temporal_boost, 1.0), 4)

    # ── Drift detector update ─────────────────────────────────────────────────
    try:
        hour = ts.hour
        feat_vec = make_feature_vector(
            meta["script_detected"], entropy_val,
            categories, len(scoring_text), hour,
        )
        get_drift_detector().update(feat_vec)
    except Exception:
        pass

    # ── Composite attack chain boost (multi-category co-occurrence) ───────────
    if len(categories) > 1:
        score = min(score * 1.18, 1.0)

    # ── High-confidence keyword floor (decisive signatures must not be diluted) ─
    if keyword_signal >= 0.90:
        score = max(score, 0.83)

    # ── Explanation assembly ─────────────────────────────────────────────────
    explanations: List[str] = []
    if keyword_signal > 0:
        explanations.append(f"Threat patterns matched: {', '.join(categories)}")
    if ngram_score >= 0.25 and ngram_families:
        explanations.append(
            f"N-gram corpus similarity ({ngram_score:.2f}): structurally resembles "
            f"{', '.join(ngram_families[:3])} attack payloads"
        )
    if entropy_val > 0.72:
        explanations.append(f"High Shannon entropy ({entropy_val:.2f}) — possible obfuscation")
    if char_anomaly > 0.50:
        explanations.append(f"Abnormal special-character density ({char_anomaly:.2f})")
    if bigram_entropy > 0.65:
        explanations.append(
            f"Bigram Markov entropy ({bigram_entropy:.2f}) — character transition pattern "
            "deviates from natural language baseline"
        )
    if pos_conc > 0.55:
        explanations.append(
            f"Positional concentration ({pos_conc:.2f}) — suspicious chars clustered "
            "(payload appended to legitimate field)"
        )
    if repetition > 0.60:
        explanations.append(f"Repetitive pattern ({repetition:.2f}) — possible fuzzing")
    if compress > 0.50:
        explanations.append(f"Compression anomaly ({compress:.2f}) — machine-generated payload")
    if burst > 0.45:
        explanations.append(f"Delimiter/operator burst ({burst:.2f}) — exploit grammar detected")
    if decoded_text != scoring_text and decoded_patterns:
        explanations.append("Encoded payload unfolded into known malicious signatures")
    if url_explanations:
        explanations.extend(url_explanations)
    if meta["evasion_suspected"]:
        explanations.append(
            f"Multilingual evasion suspected ({meta['script_detected']}, "
            f"confidence {meta['evasion_confidence']:.2f})"
        )
    if behavioural_risk >= 0.40:
        explanations.append(f"Behavioural anomaly signal ({behavioural_risk:.2f})")
    if temporal_boost > 0:
        explanations.append(
            f"Temporal risk boost (+{temporal_boost:.2f}): {', '.join(meta['temporal_signals'])}"
        )
    if not explanations:
        explanations.append("Input appears safe — all evidence layers clear")

    risk_score = round(min(score, 1.0), 3)

    if risk_score >= 0.70:
        decision = "block"
    elif risk_score >= 0.30:
        decision = "warn"
    else:
        decision = "allow"

    return risk_score, decision, patterns, explanations, meta

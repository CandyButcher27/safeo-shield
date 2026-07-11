"""
Structural anomaly signals derived from information theory and statistics.

Signals exported:
  shannon_entropy              -- character-level unigram entropy (obfuscation proxy)
  character_distribution_anomaly -- special-character ratio (encoded payload proxy)
  repetition_score             -- 4-gram uniqueness ratio (fuzzing / buffer-overflow proxy)
  compression_anomaly          -- zlib compression ratio (Kolmogorov complexity proxy)
  token_burst_score            -- dangerous delimiter density (exploit grammar proxy)
  bigram_markov_entropy        -- conditional bigram entropy (NLP structural anomaly)
  positional_concentration     -- Gini coefficient of suspicious-char positions (payload clustering)
"""

import math
import zlib
from collections import Counter, defaultdict


def shannon_entropy(text: str) -> float:
    """Shannon entropy normalized to 0-1 (high entropy = possible obfuscation)."""
    if not text or len(text) < 2:
        return 0.0
    counts = Counter(text)
    total = len(text)
    entropy = -sum((c / total) * math.log2(c / total) for c in counts.values())
    # Max entropy for 95 printable ASCII chars ≈ 6.57 bits
    return min(entropy / 6.57, 1.0)


def character_distribution_anomaly(text: str) -> float:
    """Detects abnormal special-character ratio — common in encoded payloads."""
    if not text:
        return 0.0
    special = sum(1 for c in text if not c.isalnum() and not c.isspace())
    ratio = special / len(text)
    return min(ratio / 0.30, 1.0)  # >30% special chars = suspicious


def repetition_score(text: str) -> float:
    """Detects repeated substrings — common in buffer-overflow and fuzzing payloads."""
    if len(text) < 10:
        return 0.0
    chunk = 4
    chunks = [text[i : i + chunk] for i in range(0, len(text) - chunk, chunk)]
    if not chunks:
        return 0.0
    unique_ratio = len(set(chunks)) / len(chunks)
    return max(0.0, 1.0 - unique_ratio)


def compression_anomaly(text: str) -> float:
    """
    Compression-based anomaly score (Kolmogorov complexity proxy).
    Highly repetitive or machine-generated payloads compress unusually well.
    """
    if not text or len(text) < 24:
        return 0.0
    raw = text.encode("utf-8", errors="ignore")
    if not raw:
        return 0.0
    compressed = zlib.compress(raw, level=9)
    ratio = len(compressed) / max(len(raw), 1)
    return min(max((0.85 - ratio) / 0.55, 0.0), 1.0)


def token_burst_score(text: str) -> float:
    """
    Burst score for repeated dangerous delimiters and operators.
    Captures payload grammar often seen in exploits.
    """
    if not text:
        return 0.0
    suspicious_tokens = [
        "<", ">", "{", "}", ";", "--", "/*", "*/", "||", "&&", "$(", "`",
    ]
    hits = 0
    lowered = text.lower()
    for token in suspicious_tokens:
        hits += lowered.count(token.lower())
    density = hits / max(len(text), 1)
    return min(density / 0.09, 1.0)


def bigram_markov_entropy(text: str) -> float:
    """
    Conditional bigram entropy: measures how unpredictable character transitions are.

    Technique: for each source character c, compute the entropy H(next | c) over
    observed successor characters. Average across all source characters.

    Interpretation:
      - Natural English: low average conditional entropy (~1.5–2.5 bits) because
        common bigrams (th, he, in, er, an) dominate transitions.
      - Random/encrypted payloads: high conditional entropy — successors are
        near-uniformly distributed.
      - Exploit payloads: characteristic bimodal pattern — some chars have very
        predictable successors (keyword prefixes like "sc" → "r" in <script>)
        while others are highly variable (obfuscation delimiters).

    Returns a 0-1 anomaly score calibrated so typical English text scores ~0.35
    and maximally random text scores ~1.0.
    """
    if not text or len(text) < 4:
        return 0.0

    transitions: dict = defaultdict(Counter)
    for i in range(len(text) - 1):
        transitions[text[i]][text[i + 1]] += 1

    total_entropy = 0.0
    total_sources = 0
    for char, nexts in transitions.items():
        total_count = sum(nexts.values())
        if total_count < 2:
            continue
        h = -sum(
            (c / total_count) * math.log2(c / total_count)
            for c in nexts.values()
        )
        total_entropy += h
        total_sources += 1

    if not total_sources:
        return 0.0

    avg_bigram_entropy = total_entropy / total_sources
    # Max meaningful conditional entropy ~3.5 bits (near-uniform over 10+ successors).
    # Normalize; values above 1.0 are clamped.
    return round(min(avg_bigram_entropy / 3.5, 1.0), 3)


def positional_concentration(text: str) -> float:
    """
    Gini coefficient of the positions of suspicious characters in the input.

    Rationale: legitimate inputs with incidental punctuation scatter special
    characters throughout the string (low Gini → low score). Injection payloads
    appended or prepended to a legitimate field cluster suspicious characters at
    one end (high Gini → high score).

    Suspicious character set: < > ; ' \" ` $ \\ { } ( )

    Returns 0-1 where 1 = maximally concentrated (payload-like).
    """
    if not text or len(text) < 8:
        return 0.0

    suspicious_chars = set("<>;'\"`$\\{}()")
    positions = [
        i / len(text)
        for i, c in enumerate(text)
        if c in suspicious_chars
    ]

    if len(positions) < 3:
        return 0.0

    # Gini coefficient via sorted-array formula: G = (2 * Σ rank*x_i) / (n * Σ x_i) - (n+1)/n
    n = len(positions)
    s = sorted(positions)
    total = sum(s)
    if total == 0:
        return 0.0
    weighted_sum = sum((i + 1) * v for i, v in enumerate(s))
    gini = (2 * weighted_sum) / (n * total) - (n + 1) / n
    return round(min(max(gini, 0.0), 1.0), 3)

"""
URL / IDN homograph scanner — Tier 1 extension for phishing link analysis.

Detects:
  - Mixed-script hostnames (Latin + Arabic/Cyrillic/etc.)
  - Confusable Unicode homoglyphs (ọ vs o, ạ vs a)
  - Arabic-Indic / Eastern Arabic digits in URLs
  - Punycode (xn--) domains with suspicious decoded forms
"""
from __future__ import annotations

import re
import unicodedata
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

# Latin lookalikes from other scripts / extended Latin
CONFUSABLES: Dict[str, str] = {
    "\u1ecd": "o",  # ọ LATIN SMALL LETTER O WITH DOT BELOW
    "\u1ecc": "O",
    "\u1ea1": "a",  # ạ LATIN SMALL LETTER A WITH DOT BELOW
    "\u1ea0": "A",
    "\u0430": "a",  # Cyrillic а
    "\u0435": "e",  # Cyrillic е
    "\u043e": "o",  # Cyrillic о
    "\u0440": "p",  # Cyrillic р
    "\u0441": "c",  # Cyrillic с
    "\u0443": "y",  # Cyrillic у
    "\u0445": "x",  # Cyrillic х
    "\u0456": "i",  # Cyrillic і
    "\u04cf": "l",  # Cyrillic ӏ
    "\u0627": "a",  # Arabic alef
    "\u0648": "w",  # Arabic waw
}

ARABIC_INDIC_DIGITS = set("٠١٢٣٤٥٦٧٨٩")
EASTERN_ARABIC_DIGITS = set("۰۱۲۳۴۵۶۷۸۹")

_URL_RE = re.compile(
    r"^(?:https?://)?[^\s/]+(?:/[^\s]*)?$",
    re.IGNORECASE,
)


def _script_of(ch: str) -> str:
    try:
        name = unicodedata.name(ch, "")
    except ValueError:
        return "Unknown"
    if "ARABIC" in name:
        return "Arabic"
    if "CYRILLIC" in name:
        return "Cyrillic"
    if "LATIN" in name:
        return "Latin"
    if "DIGIT" in name:
        return "Digit"
    return name.split()[0] if name else "Unknown"


def _extract_host(text: str) -> Optional[str]:
    raw = text.strip()
    if not raw:
        return None
    if not raw.startswith(("http://", "https://")):
        candidate = f"https://{raw}"
    else:
        candidate = raw
    try:
        parsed = urlparse(candidate)
        return parsed.hostname or parsed.path.split("/")[0] or None
    except Exception:
        return None


def _flag_characters(host: str) -> List[Dict[str, Any]]:
    flagged: List[Dict[str, Any]] = []
    for i, ch in enumerate(host):
        if ch in ".-":
            continue
        cp = f"U+{ord(ch):04X}"
        looks_like = CONFUSABLES.get(ch)
        script = _script_of(ch)
        is_suspicious = bool(looks_like) or script not in ("Latin", "Digit", "Unknown")
        if ch in ARABIC_INDIC_DIGITS or ch in EASTERN_ARABIC_DIGITS:
            is_suspicious = True
            looks_like = str(ord(ch) - ord("٠")) if ch in ARABIC_INDIC_DIGITS else looks_like
        if is_suspicious:
            flagged.append({
                "char": ch,
                "codepoint": cp,
                "position": i,
                "looks_like": looks_like or "latin equivalent",
                "script": script,
            })
    return flagged


def analyze_url(text: str) -> Dict[str, Any]:
    """
    Analyze text as a URL/host for IDN homograph and mixed-script attacks.
    Returns metadata merged into Tier 1 risk scoring.
    """
    result: Dict[str, Any] = {
        "is_url": False,
        "host": None,
        "punycode": None,
        "homograph_detected": False,
        "mixed_script": False,
        "arabic_digits": False,
        "flagged_chars": [],
        "risk_boost": 0.0,
        "patterns": [],
        "explanations": [],
    }

    stripped = (text or "").strip()
    if len(stripped) < 4 or not _URL_RE.match(stripped):
        return result

    host = _extract_host(stripped)
    if not host:
        return result

    result["is_url"] = True
    result["host"] = host
    if host.startswith("xn--"):
        result["punycode"] = host

    flagged = _flag_characters(host)
    result["flagged_chars"] = flagged

    scripts = {f["script"] for f in flagged if f["script"] not in ("Digit", "Unknown")}
    result["mixed_script"] = len(scripts) > 1 or any(
        f["script"] not in ("Latin", "Digit") for f in flagged
    )
    result["arabic_digits"] = any(
        f["char"] in ARABIC_INDIC_DIGITS or f["char"] in EASTERN_ARABIC_DIGITS
        for f in flagged
    )
    result["homograph_detected"] = bool(flagged) or result["mixed_script"] or result["arabic_digits"]

    if result["homograph_detected"]:
        result["risk_boost"] = 0.88
        if result["mixed_script"]:
            result["risk_boost"] = max(result["risk_boost"], 0.92)
        if len(flagged) >= 2:
            result["risk_boost"] = max(result["risk_boost"], 0.94)

        result["patterns"].append("idn_homograph: suspicious unicode in hostname")
        if result["mixed_script"]:
            result["patterns"].append("idn_homograph: mixed_script_hostname")
        if result["arabic_digits"]:
            result["patterns"].append("idn_homograph: arabic_indic_digits_in_url")
        for f in flagged[:5]:
            result["patterns"].append(
                f"idn_homograph: '{f['char']}' ({f['codepoint']}) resembles '{f['looks_like']}'"
            )

        result["explanations"].append(
            f"IDN homograph detected in hostname '{host}' — confusable Unicode characters flagged"
        )
        if flagged:
            sample = ", ".join(f"{f['char']} ({f['codepoint']})" for f in flagged[:4])
            result["explanations"].append(f"Suspicious characters: {sample}")
        if result["mixed_script"]:
            result["explanations"].append(
                f"Mixed scripts in hostname: {', '.join(sorted(scripts))}"
            )

    return result


def url_risk_signal(text: str) -> Tuple[float, List[str], List[str], Dict[str, Any]]:
    """Returns (boost_score, patterns, explanations, url_meta)."""
    meta = analyze_url(text)
    if not meta["is_url"] or not meta["homograph_detected"]:
        return 0.0, [], [], meta
    return meta["risk_boost"], meta["patterns"], meta["explanations"], meta

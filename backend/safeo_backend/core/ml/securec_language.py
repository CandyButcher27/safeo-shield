"""
Arabic / Arabizi / Urdu text normalisation for downstream pattern matching.

Shared by MultilingualAgent; maps common Arabizi digit substitutions and
Urdu-specific letters to Latin equivalents where possible.
"""
import re
from typing import Dict

# Arabizi digit → letter (common chat shorthand)
_ARABIZI_DIGIT_MAP: Dict[str, str] = {
    "2": "a",
    "3": "a",
    "5": "kh",
    "6": "t",
    "7": "h",
    "8": "q",
    "9": "s",
}

# Urdu-specific codepoints → rough Latin transliteration
_URDU_CHAR_MAP: Dict[str, str] = {
    "\u06ba": "n",  # ں
    "\u06c1": "h",  # ہ
    "\u06d2": "e",  # ے
    "\u0688": "d",  # ڈ
    "\u0691": "r",  # ڑ
    "\u0679": "t",  # ٹ
    "\u0686": "ch",  # چ
    "\u0698": "zh",  # ژ
    "\u06af": "g",  # گ
    "\u06be": "h",  # ھ
    "\u067e": "p",  # پ
}


def normalise_arabic_block(text: str) -> str:
    """Strip diacritics and normalise Arabic presentation forms."""
    if not text:
        return ""
    # Remove Arabic diacritics (tashkeel)
    out = re.sub(r"[\u064b-\u065f\u0670]", "", text)
    return out


def normalise_arabizi(text: str) -> str:
    """Expand common Arabizi digit substitutions in Latin text."""
    out = text.lower()
    for digit, letter in _ARABIZI_DIGIT_MAP.items():
        out = out.replace(digit, letter)
    return out


def normalise_urdu_chars(text: str) -> str:
    """Map Urdu-specific letters to Latin approximations."""
    out = text
    for char, latin in _URDU_CHAR_MAP.items():
        out = out.replace(char, latin)
    return out


def normalise_mixed_script(text: str) -> str:
    """Full normalisation pipeline for multilingual ERP payloads."""
    if not text:
        return ""
    step = normalise_arabic_block(text)
    step = normalise_urdu_chars(step)
    step = normalise_arabizi(step)
    # Collapse repeated whitespace
    return re.sub(r"\s+", " ", step).strip()

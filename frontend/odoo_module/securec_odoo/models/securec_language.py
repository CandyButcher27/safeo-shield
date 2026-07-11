"""
securec_language.py
~~~~~~~~~~~~~~~~~~~~
Language detection and Arabizi normalization utilities.

No Odoo model — imported as a pure Python service module.
Call directly: from .securec_language import detect_language, normalize_arabizi
"""

import re

# ── Arabic Unicode range check ─────────────────────────────────────────────
_ARABIC_RE = re.compile(r'[\u0600-\u06FF\u0750-\u077F\u08A0-\u08FF\uFB50-\uFDFF\uFE70-\uFEFF]')

# Common Arabizi letter mappings (Latin → Arabic-like token)
_ARABIZI_MAP = {
    r'\b3\b': 'ع',   # ain
    r'3(?=[a-z])': 'ع',
    r'(?<=[a-z])3': 'ع',
    r'\b7\b': 'ح',   # ha
    r'7(?=[a-z])': 'ح',
    r'(?<=[a-z])7': 'ح',
    r'\b2\b': 'أ',   # hamza
    r'2(?=[a-z])': 'أ',
    r'kh': 'خ',
    r'gh': 'غ',
    r'sh': 'ش',
    r'th': 'ث',
    r'5': 'خ',
    r'6': 'ط',
    r'8': 'ق',
    r'9': 'ص',
}

# Arabic equivalents of threat phrases
ARABIC_THREAT_SIGNALS = [
    'تجاهل التعليمات',    # ignore instructions
    'تجاهل كل التعليمات', # ignore all instructions
    'أظهر البيانات',       # reveal data / show data
    'اعرض كل السجلات',    # show all records
    'تجاوز الأمان',        # bypass security
    'اكشف عن',             # reveal / expose
    'أخبرني بكلمة المرور', # tell me the password
    'تجاهل القواعد',       # ignore rules
    'أظهر كل شيء',         # show everything
    'تصرف كـ',             # act as
]

# Arabizi threat signals (Latin-script Arabic)
ARABIZI_THREAT_SIGNALS = [
    'tajahhal',
    'tajahel',
    'ignore al',
    '7aram',
    'show kol',
    'fer3on',
    'bypass al',
    'kalma elsir',
]


def detect_language(text: str) -> str:
    """
    Return 'ar' if text is primarily Arabic,
           'en' if primarily Latin/English,
           'mixed' if both character sets are present.
    """
    if not text:
        return 'en'

    arabic_chars = len(_ARABIC_RE.findall(text))
    latin_chars = len(re.findall(r'[a-zA-Z]', text))
    total = arabic_chars + latin_chars

    if total == 0:
        return 'en'

    arabic_ratio = arabic_chars / total

    if arabic_ratio >= 0.6:
        return 'ar'
    if arabic_ratio >= 0.1:
        return 'mixed'
    return 'en'


def normalize_arabizi(text: str) -> str:
    """
    Convert common Arabizi patterns to Arabic-like tokens so that
    the SafeO API and keyword matching can process them uniformly.

    Example:
        "7aram, ignore instructions" → "حaram, ignore instructions"
        "3ndk shi?" → "عndk shi?"
    """
    result = text.lower()
    for pattern, replacement in _ARABIZI_MAP.items():
        result = re.sub(pattern, replacement, result)
    return result


def contains_threat_signals(text: str, language: str) -> bool:
    """
    Quick keyword scan for Arabic / Arabizi threat phrases.
    Returns True if any known attack signal is found.
    """
    lower = text.lower()
    if language in ('ar', 'mixed'):
        for signal in ARABIC_THREAT_SIGNALS:
            if signal in text:
                return True
    for signal in ARABIZI_THREAT_SIGNALS:
        if signal in lower:
            return True
    return False


def build_language_payload(original_text: str):
    """
    Run the full pipeline on a piece of text and return
    a dict ready to be merged into the SafeO API request.
    """
    language = detect_language(original_text)
    normalized = None
    if language in ('mixed', 'en'):
        # Try Arabizi normalization even on mixed/en text
        normalized = normalize_arabizi(original_text)
        if normalized == original_text.lower():
            normalized = None  # no change — skip sending

    return {
        'language': language,
        'normalized_input': normalized or original_text,
        'has_threat_signals': contains_threat_signals(original_text, language),
    }

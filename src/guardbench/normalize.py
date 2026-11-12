"""Input restoration: undo cheap obfuscation before any scanner reads the text.

Maps to MITRE ATLAS mitigation AML.M0010 (Input Restoration) and answers
technique AML.T0068 (LLM Prompt Obfuscation).
"""

from __future__ import annotations

import base64
import binascii
import re
import unicodedata

_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s"})
_BASE64 = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
_SPACED = re.compile(r"(?:\b\w\s+){4,}\w\b")


def _strip_format_chars(text: str) -> str:
    """Remove zero-width and other invisible format characters."""
    return "".join(c for c in text if unicodedata.category(c) != "Cf")


def _decode_base64(text: str) -> list[str]:
    out = []
    for token in _BASE64.findall(text):
        try:
            decoded = base64.b64decode(token, validate=True).decode("utf-8")
        except (binascii.Error, UnicodeDecodeError):
            continue
        if decoded.isprintable():
            out.append(decoded)
    return out


def _collapse_spaced(text: str) -> str:
    """Turn 'i g n o r e   a l l' back into 'ignore all'."""

    def join(match: re.Match) -> str:
        words = re.split(r"\s{2,}", match.group(0))
        return " ".join(re.sub(r"\s+", "", w) for w in words)

    return _SPACED.sub(join, text)


def normalize(text: str) -> str:
    """Return the text plus every restored variant, joined for scanning.

    The original is kept so that a scanner never sees less than the attacker
    sent. Variants: Unicode NFKC folding, invisible characters removed,
    letter-spacing collapsed, leetspeak mapped to letters, base64 decoded.
    """
    folded = _strip_format_chars(unicodedata.normalize("NFKC", text))
    variants = [folded, _collapse_spaced(folded), folded.translate(_LEET), *_decode_base64(folded)]
    seen: list[str] = []
    for v in variants:
        if v not in seen:
            seen.append(v)
    return "\n".join(seen)

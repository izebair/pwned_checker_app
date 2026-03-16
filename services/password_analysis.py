"""Local password analysis utilities.

This module implements non‑networked heuristics for assessing password
strength and reuse. It deliberately avoids storing or returning the
cleartext passwords themselves. Where necessary, cryptographic hashes
are used as stand‑ins to identify reused secrets.
"""

from __future__ import annotations

import hashlib
import re
from typing import Dict, Iterable, Tuple, List


# Common patterns indicative of weak passwords. These are checked in a
# case‑insensitive manner.
COMMON_PATTERNS = [
    "123456", "password", "passwort", "qwerty", "admin", "welcome",
    "letmein", "abc123", "iloveyou", "monkey", "dragon", "111111",
]


def is_weak_password(password: str) -> Tuple[bool, str]:
    """Determine whether a password is considered weak.

    The following simple heuristics are applied:

    * Length shorter than 12 characters.
    * Consists solely of alphabetic characters.
    * Contains a commonly used pattern such as "123456" or "password".

    Args:
        password: The cleartext password to evaluate.

    Returns:
        A tuple ``(is_weak, reason)`` where ``is_weak`` is ``True`` if any
        heuristic triggered and ``reason`` is a descriptive string. If the
        password is not considered weak, ``reason`` is an empty string.
    """
    reasons: List[str] = []
    # Check minimum length
    if len(password) < 12:
        reasons.append("Länge unter 12 Zeichen")
    # Check if only letters (no digits or symbols)
    if password.isalpha():
        reasons.append("enthält nur Buchstaben")
    # Check for common patterns
    lowered = password.lower()
    for pattern in COMMON_PATTERNS:
        if pattern in lowered:
            reasons.append(f"enthält häufiges Muster '{pattern}'")
            break

    is_weak = bool(reasons)
    return is_weak, "; ".join(reasons)


def detect_reuse(entries: Iterable[Dict[str, str]]) -> Dict[str, int]:
    """Detect reused passwords across a collection of credential entries.

    Each entry must provide a ``password`` key. Passwords are hashed using
    SHA‑1 and the hex digest is used as a dictionary key. This approach
    prevents the original passwords from being revealed outside of the
    analysis phase.

    Args:
        entries: An iterable of credential dictionaries.

    Returns:
        A mapping of SHA‑1 hex digests to the number of times that digest
        appears in ``entries``.
    """
    counts: Dict[str, int] = {}
    for entry in entries:
        pw = entry.get("password")
        if not pw:
            continue
        sha1_hash = hashlib.sha1(pw.encode("utf-8")).hexdigest().upper()
        counts[sha1_hash] = counts.get(sha1_hash, 0) + 1
    return counts

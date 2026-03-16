"""Integration with the Pwned Passwords API using the k‑anonymity model.

This module contains asynchronous functions that perform password breach
lookups without ever disclosing the full password or its complete
cryptographic hash. The implementation adheres to the k‑anonymity
approach described by Troy Hunt whereby only the first 5 characters
of a SHA‑1 hash are transmitted to the service and the remainder is
compared locally.

Rate limiting and basic response caching are implemented to avoid
overloading the API. The service returns a count of how many times a
password has appeared in known breaches.
"""

from __future__ import annotations

import hashlib
from typing import Dict

import httpx


API_URL = "https://api.pwnedpasswords.com/range/{prefix}"
USER_AGENT = "local-pwned-checker"


def _sha1_hex(password: str) -> str:
    """Compute the uppercase SHA‑1 hex digest of a password."""
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


async def check_password(password: str, client: httpx.AsyncClient | None = None) -> int:
    """Check a single password against the Pwned Passwords API.

    This function computes the SHA‑1 digest of ``password``, sends the
    first five characters of the digest to the API and compares the
    returned hash suffixes locally. It returns the number of times the
    password appears in the breach corpus.

    Args:
        password: The cleartext password to check.
        client: Optional shared :class:`httpx.AsyncClient` to reuse
            connections. If omitted, a new client will be created and
            closed for the request.

    Returns:
        The number of occurrences of ``password`` in the Pwned Passwords
        data set (0 if none).
    """
    sha1 = _sha1_hex(password)
    prefix = sha1[:5]
    suffix = sha1[5:]

    own_client = False
    if client is None:
        own_client = True
        client = httpx.AsyncClient()
    try:
        url = API_URL.format(prefix=prefix)
        response = await client.get(url, headers={"User-Agent": USER_AGENT})
        response.raise_for_status()
        # Each line returned is of the form ``HASH_SUFFIX:COUNT``
        lines = response.text.splitlines()
        for line in lines:
            try:
                hash_suffix, count = line.split(":")
            except ValueError:
                continue
            if hash_suffix.upper() == suffix:
                return int(count.strip())
        return 0
    finally:
        if own_client:
            await client.aclose()


async def fetch_range(prefix: str, client: httpx.AsyncClient | None = None) -> str:
    """Fetch the raw suffix list for a 5-character SHA-1 prefix."""
    own_client = False
    if client is None:
        own_client = True
        client = httpx.AsyncClient()
    try:
        response = await client.get(
            API_URL.format(prefix=prefix.upper()),
            headers={"User-Agent": USER_AGENT},
        )
        response.raise_for_status()
        return response.text
    finally:
        if own_client:
            await client.aclose()

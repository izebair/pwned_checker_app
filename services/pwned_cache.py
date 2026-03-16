"""Persistent local cache for Pwned Passwords hash ranges.

The app stores the 5-character SHA-1 hash range responses on disk so
future password checks can reuse them locally. Missing ranges are
downloaded on demand, and cached ranges can be refreshed from the web UI.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable

import httpx

from . import pwned_passwords


CACHE_DIR = Path(__file__).resolve().parents[1] / "data" / "pwned_password_prefixes"


@dataclass
class CacheUpdateSummary:
    cached_prefixes: int
    downloaded_prefixes: int
    refreshed_prefixes: int


def ensure_cache_dir() -> Path:
    """Create the cache directory if needed."""
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    return CACHE_DIR


def prefix_for_password(password: str) -> str:
    """Return the first five SHA-1 characters for a password."""
    return pwned_passwords._sha1_hex(password)[:5]


def prefixes_for_passwords(passwords: Iterable[str]) -> list[str]:
    """Return sorted unique hash prefixes for a list of passwords."""
    return sorted({prefix_for_password(password) for password in passwords if password})


def cache_path(prefix: str) -> Path:
    """Return the on-disk location for a cached prefix response."""
    return ensure_cache_dir() / f"{prefix.upper()}.txt"


def parse_range_text(text: str) -> Dict[str, int]:
    """Convert an API response body into a suffix-to-count mapping."""
    suffix_counts: Dict[str, int] = {}
    for line in text.splitlines():
        try:
            suffix_hash, count = line.split(":")
        except ValueError:
            continue
        suffix_counts[suffix_hash.strip().upper()] = int(count.strip())
    return suffix_counts


def read_cached_prefix(prefix: str) -> Dict[str, int] | None:
    """Read a cached prefix response if it exists."""
    path = cache_path(prefix)
    if not path.exists():
        return None
    return parse_range_text(path.read_text(encoding="utf-8"))


def cache_stats() -> Dict[str, object]:
    """Return basic cache information for the UI."""
    directory = ensure_cache_dir()
    files = sorted(directory.glob("*.txt"))
    last_updated = None
    if files:
        latest_ts = max(path.stat().st_mtime for path in files)
        last_updated = datetime.fromtimestamp(latest_ts, tz=timezone.utc).isoformat()
    return {
        "cache_dir": str(directory),
        "cached_prefixes": len(files),
        "last_updated": last_updated,
    }


async def ensure_prefixes(
    prefixes: Iterable[str],
    *,
    force_refresh: bool = False,
    rate_limit: float = 1.5,
) -> CacheUpdateSummary:
    """Download any missing prefixes and optionally refresh existing ones."""
    unique_prefixes = sorted({prefix.upper() for prefix in prefixes if prefix})
    downloaded = 0
    refreshed = 0

    async with httpx.AsyncClient() as client:
        first_request = True
        for prefix in unique_prefixes:
            path = cache_path(prefix)
            existed_before = path.exists()
            needs_download = force_refresh or not existed_before
            if not needs_download:
                continue
            if not first_request and rate_limit:
                await asyncio.sleep(rate_limit)
            response_text = await pwned_passwords.fetch_range(prefix, client=client)
            path.write_text(response_text, encoding="utf-8")
            if existed_before:
                refreshed += 1
            else:
                downloaded += 1
            first_request = False

    stats = cache_stats()
    return CacheUpdateSummary(
        cached_prefixes=int(stats["cached_prefixes"]),
        downloaded_prefixes=downloaded,
        refreshed_prefixes=refreshed,
    )


async def refresh_cached_prefixes(rate_limit: float = 1.5) -> CacheUpdateSummary:
    """Redownload every cached prefix file."""
    prefixes = [path.stem for path in ensure_cache_dir().glob("*.txt")]
    return await ensure_prefixes(prefixes, force_refresh=True, rate_limit=rate_limit)


async def check_passwords(passwords: Iterable[str]) -> tuple[Dict[str, int], CacheUpdateSummary]:
    """Ensure cached data exists for the given passwords, then query locally."""
    password_list = [password for password in passwords if password]
    summary = await ensure_prefixes(prefixes_for_passwords(password_list))
    results: Dict[str, int] = {}
    suffix_maps: Dict[str, Dict[str, int]] = {}

    for password in password_list:
        sha1 = pwned_passwords._sha1_hex(password)
        prefix = sha1[:5]
        suffix = sha1[5:]
        if prefix not in suffix_maps:
            suffix_maps[prefix] = read_cached_prefix(prefix) or {}
        results[password] = suffix_maps[prefix].get(suffix, 0)

    return results, summary

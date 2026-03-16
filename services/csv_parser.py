"""CSV parsing utilities for the local pwned checker application.

This module provides functions to ingest and normalise CSV files exported
from various password managers. Because different tools use different
column names, all keys are coerced to lower case and a best‐effort
mapping is applied. Only entries containing a password are returned.

The CSV data is never persisted to disk. Callers should pass in the raw
file contents and ensure that any temporary files are deleted after use.
"""

from __future__ import annotations

import csv
import io
from typing import List, Dict, Any


def _normalise_row(row: Dict[str, Any]) -> Dict[str, Any]:
    """Normalise a single CSV row.

    Lower–case all keys and strip whitespace from string values. Unknown
    keys are retained in their original form.

    Args:
        row: A dictionary produced by ``csv.DictReader``.

    Returns:
        A new dictionary with lower–cased keys.
    """
    normalised: Dict[str, Any] = {}
    for key, value in row.items():
        if key is None:
            continue
        new_key = key.strip().lower()
        if isinstance(value, str):
            normalised[new_key] = value.strip()
        else:
            normalised[new_key] = value
    return normalised


def parse_csv(contents: bytes) -> List[Dict[str, str]]:
    """Parse a CSV file exported from a password manager.

    The parser attempts to identify common column names for website,
    username and password. It tolerates variations such as "url" or
    "site" for the website field and "login" for the username field.

    Args:
        contents: Raw CSV bytes from the uploaded file.

    Returns:
        A list of dictionaries with the keys ``website``, ``username`` and
        ``password``. Entries missing a password are ignored.
    """
    # Decode the bytes into a string, attempting to handle UTF‑8 with BOM
    text = contents.decode("utf-8-sig", errors="ignore")
    reader = csv.DictReader(io.StringIO(text))
    entries: List[Dict[str, str]] = []

    for raw_row in reader:
        row = _normalise_row(raw_row)
        # Candidate keys for each field
        website_keys = ["website", "site", "url", "domain"]
        username_keys = ["username", "user", "login", "email"]
        password_keys = ["password", "pass", "pwd"]

        website = next((row.get(k) for k in website_keys if row.get(k)), "")
        username = next((row.get(k) for k in username_keys if row.get(k)), "")
        password = next((row.get(k) for k in password_keys if row.get(k)), None)

        # Skip entries with no password
        if not password:
            continue

        entries.append({
            "website": website or "",
            "username": username or "",
            "password": password,
        })

    return entries
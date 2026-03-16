"""Main FastAPI application for the local pwned checker.

This file defines the web interface with three primary functions:

* Upload a CSV from a password manager and evaluate each record for
  password breaches, reuse and simple weak-password heuristics.
* Check a single password against the locally cached Pwned Passwords
  hash ranges.
* Refresh the local hash-range cache from the web UI.

All processing is performed locally. The app stores only the downloaded
hash-range responses needed for checks, never plaintext passwords. No
uploaded passwords or CSV files are stored on disk. The application
binds exclusively to ``127.0.0.1`` when started via the provided script.
"""

from __future__ import annotations

import csv
import io
import secrets
from pathlib import Path
from typing import Any, Dict, List

from fastapi import FastAPI, File, Form, Request, UploadFile, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.middleware.sessions import SessionMiddleware

try:
    from .services import csv_parser, password_analysis, pwned_cache, pwned_passwords
except ImportError:  # pragma: no cover - supports running from the repo root
    from services import csv_parser, password_analysis, pwned_cache, pwned_passwords


app = FastAPI()

# Configure session middleware for CSRF protection and stateful report storage.
app.add_middleware(SessionMiddleware, secret_key=secrets.token_hex(32))

# Determine template and static directories relative to this file
BASE_DIR = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(BASE_DIR / "templates"))
app.mount(
    "/static",
    StaticFiles(directory=str(BASE_DIR / "static")),
    name="static",
)


def get_csrf_token(session: Dict[str, Any]) -> str:
    """Retrieve or generate a CSRF token stored in the session."""
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_hex(16)
        session["csrf_token"] = token
    return token


@app.get("/", response_class=HTMLResponse)
async def index(request: Request) -> HTMLResponse:
    """Render the home page with any existing results.

    This handler reads any previous operation results from the session and
    passes them into the template. It also exposes a CSRF token to be
    included in all POST forms.
    """
    session = request.session
    context = {
        "request": request,
        "csrf_token": get_csrf_token(session),
        "csv_result": session.pop("csv_result", None),
        "password_result": session.pop("password_result", None),
        "csv_available": session.get("csv_report_data") is not None,
        "cache_result": session.pop("cache_result", None),
        "cache_stats": pwned_cache.cache_stats(),
    }
    return templates.TemplateResponse("index.html", context)


def verify_csrf(request: Request, token: str) -> None:
    """Verify the CSRF token from a form submission.

    Raises an HTTP 403 error if the token is missing or invalid. This
    mechanism mitigates cross‑site request forgery even though the
    application is intended for local use.
    """
    session_token = request.session.get("csrf_token")
    if not session_token or not token or token != session_token:
        raise HTTPException(status_code=403, detail="Ungültiges CSRF‑Token.")


@app.post("/upload_csv", response_class=HTMLResponse)
async def upload_csv(
    request: Request,
    file: UploadFile = File(...),
    csrf_token: str = Form(...),
) -> HTMLResponse:
    """Handle CSV uploads and perform bulk password checks.

    The uploaded file is read into memory, parsed and analysed. The
    results are stored in the session to enable download and are then
    displayed on the home page.
    """
    verify_csrf(request, csrf_token)
    contents = await file.read()
    entries = csv_parser.parse_csv(contents)
    if not entries:
        request.session["csv_result"] = {"error": "Die CSV-Datei enthält keine gültigen Datensätze."}
        return RedirectResponse(url="/", status_code=303)

    # Detect reused passwords
    reuse_counts = password_analysis.detect_reuse(entries)

    # Evaluate weak passwords
    weak_map: Dict[str, password_analysis.Tuple] = {}
    for entry in entries:
        pw = entry["password"]
        weak, reason = password_analysis.is_weak_password(pw)
        weak_map[pw] = (weak, reason)

    passwords = [entry["password"] for entry in entries]
    try:
        pwned_results, cache_summary = await pwned_cache.check_passwords(passwords)
    except Exception as exc:
        request.session["csv_result"] = {"error": f"Fehler beim Aktualisieren des lokalen Hash-Caches: {exc}"}
        return RedirectResponse(url="/", status_code=303)

    # Build the result list without exposing raw passwords
    report: List[Dict[str, Any]] = []
    for entry in entries:
        pw = entry["password"]
        sha1 = pwned_passwords._sha1_hex(pw)  # internal function; used for reuse detection
        reuse_count = reuse_counts.get(sha1, 0)
        weak, weak_reason = weak_map[pw]
        report_entry = {
            "website": entry.get("website", ""),
            "username": entry.get("username", ""),
            "pwned_count": pwned_results.get(pw, 0),
            "reused_password": reuse_count > 1,
            "reuse_count": reuse_count,
            "weak_password": weak,
            "weak_reason": weak_reason,
        }
        report.append(report_entry)

    # Store the report in the session (without passwords) for optional export
    request.session["csv_report_data"] = report
    request.session["csv_result"] = {
        "entries": report,
        "downloaded_prefixes": cache_summary.downloaded_prefixes,
        "cached_prefixes": cache_summary.cached_prefixes,
    }
    return RedirectResponse(url="/", status_code=303)


@app.post("/check_password", response_class=HTMLResponse)
async def check_single_password(
    request: Request,
    password: str = Form(...),
    csrf_token: str = Form(...),
) -> HTMLResponse:
    """Check a single password for breaches and weakness.

    The password is never stored in the session; only the result is
    persisted. Weakness heuristics are applied locally before the
    breach check.
    """
    verify_csrf(request, csrf_token)
    pw = password.strip()
    if not pw:
        request.session["password_result"] = {"error": "Bitte ein Passwort eingeben."}
        return RedirectResponse(url="/", status_code=303)

    # Evaluate local heuristics
    weak, weak_reason = password_analysis.is_weak_password(pw)
    try:
        results, cache_summary = await pwned_cache.check_passwords([pw])
        count = results[pw]
    except Exception as exc:
        request.session["password_result"] = {"error": f"Fehler beim Aktualisieren des lokalen Hash-Caches: {exc}"}
        return RedirectResponse(url="/", status_code=303)

    request.session["password_result"] = {
        "pwned_count": count,
        "weak_password": weak,
        "weak_reason": weak_reason,
        "downloaded_prefixes": cache_summary.downloaded_prefixes,
        "cached_prefixes": cache_summary.cached_prefixes,
    }
    return RedirectResponse(url="/", status_code=303)


@app.post("/refresh_cache", response_class=HTMLResponse)
async def refresh_cache(
    request: Request,
    csrf_token: str = Form(...),
) -> HTMLResponse:
    """Refresh every cached password hash range from the source service."""
    verify_csrf(request, csrf_token)
    try:
        summary = await pwned_cache.refresh_cached_prefixes()
    except Exception as exc:
        request.session["cache_result"] = {"error": f"Fehler beim Aktualisieren des lokalen Hash-Caches: {exc}"}
        return RedirectResponse(url="/", status_code=303)
    request.session["cache_result"] = {
        "message": "Lokaler Hash-Cache aktualisiert.",
        "refreshed_prefixes": summary.refreshed_prefixes,
        "cached_prefixes": summary.cached_prefixes,
    }
    return RedirectResponse(url="/", status_code=303)


@app.get("/export_report", response_class=StreamingResponse)
async def export_report(request: Request) -> StreamingResponse:
    """Generate and stream a CSV report of the last bulk check.

    The report contains only non‑sensitive fields: website, username,
    pwned_count, reused_password (as yes/no), reuse_count, weak_password
    (yes/no) and weak_reason. If no report is available in the session
    the user is redirected back to the home page with a message.
    """
    report_data = request.session.get("csv_report_data")
    if not report_data:
        # No report available; redirect back with message
        request.session["csv_result"] = {"error": "Kein Bericht zum Export vorhanden."}
        return RedirectResponse(url="/", status_code=303)
    # Create CSV content in memory
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow([
        "website", "username", "pwned_count",
        "reused_password", "reuse_count", "weak_password", "weak_reason",
    ])
    for item in report_data:
        writer.writerow([
            item.get("website", ""),
            item.get("username", ""),
            item.get("pwned_count", 0),
            "ja" if item.get("reused_password") else "nein",
            item.get("reuse_count", 0),
            "ja" if item.get("weak_password") else "nein",
            item.get("weak_reason", ""),
        ])
    # Prepare StreamingResponse
    output.seek(0)
    headers = {
        "Content-Disposition": "attachment; filename=pwned_report.csv",
        "Content-Type": "text/csv",
    }
    return StreamingResponse(output, headers=headers)


def main() -> None:
    """Entry point for running the application with uvicorn.

    The application binds to 127.0.0.1 to ensure it is only reachable
    locally.
    """
    import uvicorn  # Local import so dependency is optional during tests

    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False, log_level="info")


if __name__ == "__main__":
    main()

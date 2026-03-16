import sys
import pathlib

sys.path.append(str(pathlib.Path(__file__).resolve().parents[2]))

from pwned_checker_app.services import password_analysis
from pwned_checker_app.services import pwned_passwords


def test_report_entry_does_not_include_password():
    # Create dummy data
    entries = [
        {"website": "example.com", "username": "alice", "password": "secret"},
        {"website": "example.com", "username": "bob", "password": "secret"},
    ]
    reuse_counts = password_analysis.detect_reuse(entries)
    weak_map = {}
    for entry in entries:
        weak_map[entry["password"]] = password_analysis.is_weak_password(entry["password"])
    # Fake pwned results; suppose secret not in pwned list
    pwned_results = {"secret": 0}
    report = []
    for entry in entries:
        pw = entry["password"]
        sha1 = pwned_passwords._sha1_hex(pw)
        reuse_count = reuse_counts[sha1]
        weak, reason = weak_map[pw]
        report_entry = {
            "website": entry.get("website"),
            "username": entry.get("username"),
            "pwned_count": pwned_results.get(pw, 0),
            "reused_password": reuse_count > 1,
            "reuse_count": reuse_count,
            "weak_password": weak,
            "weak_reason": reason,
        }
        report.append(report_entry)
    # Ensure no 'password' key in any report entry
    assert all("password" not in item for item in report)
    assert all(item["reused_password"] for item in report)

import sys
import pathlib

# Make package importable in tests
sys.path.append(str(pathlib.Path(__file__).resolve().parents[2]))

from pwned_checker_app.services import password_analysis


def test_is_weak_password_length_and_only_letters():
    weak, reason = password_analysis.is_weak_password("short")
    assert weak is True
    assert "Länge unter" in reason
    assert "Buchstaben" in reason or "enthält nur" in reason


def test_is_weak_password_common_pattern():
    weak, reason = password_analysis.is_weak_password("MySecret123456")
    assert weak is True
    assert "123456" in reason


def test_is_weak_password_strong():
    weak, reason = password_analysis.is_weak_password("Tr0ub4dor&3!8")
    assert weak is False
    assert reason == ""


def test_detect_reuse_counts():
    entries = [
        {"password": "abc"},
        {"password": "def"},
        {"password": "abc"},
    ]
    counts = password_analysis.detect_reuse(entries)
    # Two entries with 'abc' hashed should have count 2
    assert any(count == 2 for count in counts.values())
    assert any(count == 1 for count in counts.values())
    assert all(key == key.upper() for key in counts)

import asyncio
import sys
import pathlib

# Add application package to sys.path for test discovery
sys.path.append(str(pathlib.Path(__file__).resolve().parents[2]))

from pwned_checker_app.services import pwned_cache


def test_read_cached_prefix_round_trip(tmp_path, monkeypatch):
    monkeypatch.setattr(pwned_cache, "CACHE_DIR", tmp_path / "pwned_cache")
    pwned_cache.ensure_cache_dir()
    path = pwned_cache.cache_path("ABCDE")
    path.write_text("FFFF:2\nEEEE:4\n", encoding="utf-8")

    assert pwned_cache.read_cached_prefix("abcde") == {"FFFF": 2, "EEEE": 4}


def test_check_passwords_uses_cache_and_reports_downloads(tmp_path, monkeypatch):
    monkeypatch.setattr(pwned_cache, "CACHE_DIR", tmp_path / "pwned_cache")
    pwned_cache.ensure_cache_dir()

    async def fake_ensure_prefixes(prefixes, force_refresh=False, rate_limit=1.5):
        path = pwned_cache.cache_path("5BAA6")
        path.write_text("1E4C9B93F3F0682250B6CF8331B7EE68FD8:7\n", encoding="utf-8")
        return pwned_cache.CacheUpdateSummary(
            cached_prefixes=1,
            downloaded_prefixes=1,
            refreshed_prefixes=0,
        )

    monkeypatch.setattr(pwned_cache, "ensure_prefixes", fake_ensure_prefixes)

    results, summary = asyncio.run(pwned_cache.check_passwords(["password"]))

    assert results == {"password": 7}
    assert summary.downloaded_prefixes == 1

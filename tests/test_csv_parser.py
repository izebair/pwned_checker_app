import textwrap
import sys
import pathlib

# Ensure the application package is discoverable when running tests.
sys.path.append(str(pathlib.Path(__file__).resolve().parents[2]))

from pwned_checker_app.services import csv_parser


def test_parse_csv_varied_headers():
    # CSV with different header names for website, username and password
    csv_data = textwrap.dedent("""
        site,login,pwd
        example.com,alice,secret1
        test.org,bob,passw0rd
    """).strip()
    entries = csv_parser.parse_csv(csv_data.encode("utf-8"))
    assert len(entries) == 2
    assert entries[0]["website"] == "example.com"
    assert entries[0]["username"] == "alice"
    assert entries[0]["password"] == "secret1"


def test_parse_csv_ignores_missing_password():
    csv_data = textwrap.dedent("""
        website,username,password
        example.com,alice,
        test.org,bob,passw0rd
    """).strip()
    entries = csv_parser.parse_csv(csv_data.encode("utf-8"))
    # Should skip the first row where password is empty
    assert len(entries) == 1
    assert entries[0]["website"] == "test.org"
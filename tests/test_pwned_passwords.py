import sys
import pathlib

# Add application package to sys.path for test discovery
sys.path.append(str(pathlib.Path(__file__).resolve().parents[2]))

from pwned_checker_app.services import pwned_passwords


def test_sha1_hex_uppercase():
    digest = pwned_passwords._sha1_hex("password")
    # SHA1("password") = "5baa61e4c9b93f3f0682250b6cf8331b7ee68fd8"
    assert digest == "5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8"


def test_prefix_length_for_sha1_hex():
    # Ensure the SHA‑1 digest is 40 characters and the prefix method works
    pw = "password1"
    sha1 = pwned_passwords._sha1_hex(pw)
    assert len(sha1) == 40
    prefix = sha1[:5]
    assert len(prefix) == 5
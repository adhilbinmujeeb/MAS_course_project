"""
Unit tests for Person A's ingestion module.

Run with: pytest test_apk_parser.py -v

Most tests here use synthetic zip files so they run without needing a real
APK on disk. Add a `samples/` folder with real benign APKs (from F-Droid)
for the integration-style tests marked below.
"""

import zipfile
from pathlib import Path

import pytest

from apk_parser import validate_apk, check_structural_anomalies, parse_apk

SAMPLES_DIR = Path(__file__).parent / "samples"


# ----------------------------------------------------------------------
# Validation tests (synthetic, no real APK needed)
# ----------------------------------------------------------------------

def test_validate_rejects_missing_file(tmp_path):
    with pytest.raises(ValueError, match="does not exist"):
        validate_apk(tmp_path / "nope.apk")


def test_validate_rejects_non_zip(tmp_path):
    fake = tmp_path / "notazip.apk"
    fake.write_text("just some text, not a zip")
    with pytest.raises(ValueError, match="Not a valid ZIP"):
        validate_apk(fake)


def test_validate_rejects_zip_without_manifest(tmp_path):
    fake = tmp_path / "no_manifest.apk"
    with zipfile.ZipFile(fake, "w") as z:
        z.writestr("classes.dex", b"fake dex bytes")
    with pytest.raises(ValueError, match="AndroidManifest"):
        validate_apk(fake)


def test_validate_rejects_zip_without_dex(tmp_path):
    fake = tmp_path / "no_dex.apk"
    with zipfile.ZipFile(fake, "w") as z:
        z.writestr("AndroidManifest.xml", b"fake manifest bytes")
    with pytest.raises(ValueError, match="classes.dex"):
        validate_apk(fake)


def test_validate_accepts_minimal_valid_structure(tmp_path):
    ok = tmp_path / "minimal.apk"
    with zipfile.ZipFile(ok, "w") as z:
        z.writestr("AndroidManifest.xml", b"fake manifest bytes")
        z.writestr("classes.dex", b"fake dex bytes")
    assert validate_apk(ok) is True


# ----------------------------------------------------------------------
# Structural anomaly tests
# ----------------------------------------------------------------------

def test_detects_duplicate_zip_entries(tmp_path):
    dup = tmp_path / "dup.apk"
    # zipfile allows writing duplicate names directly to the archive
    with zipfile.ZipFile(dup, "w") as z:
        z.writestr("AndroidManifest.xml", b"a")
        z.writestr("classes.dex", b"b")
        z.writestr("res/layout/main.xml", b"c1")
        z.writestr("res/layout/main.xml", b"c2")  # duplicate

    anomalies = check_structural_anomalies(dup)
    types = [a["type"] for a in anomalies]
    assert "duplicate_zip_entries" in types


def test_no_false_positive_anomalies_on_clean_zip(tmp_path):
    clean = tmp_path / "clean.apk"
    with zipfile.ZipFile(clean, "w") as z:
        z.writestr("AndroidManifest.xml", b"a")
        z.writestr("classes.dex", b"b")
        z.writestr("res/layout/main.xml", b"c")

    anomalies = check_structural_anomalies(clean)
    assert anomalies == []


# ----------------------------------------------------------------------
# End-to-end orchestration test (invalid path, no androguard needed)
# ----------------------------------------------------------------------

def test_parse_apk_reports_invalid_status_cleanly(tmp_path):
    fake = tmp_path / "broken.apk"
    fake.write_bytes(b"PK\x03\x04not really a full zip")  # looks zip-ish, isn't valid

    result = parse_apk(fake)
    assert result["status"] in ("invalid", "parse_error")
    assert result["error"] is not None
    # Must NOT crash the whole pipeline — always returns a dict
    assert isinstance(result, dict)


# ----------------------------------------------------------------------
# Integration tests against a real APK — skipped if no sample provided
# ----------------------------------------------------------------------

def _first_sample():
    if SAMPLES_DIR.exists():
        apks = list(SAMPLES_DIR.glob("*.apk"))
        if apks:
            return apks[0]
    return None


@pytest.mark.skipif(_first_sample() is None, reason="No sample APK in ./samples/")
def test_parse_real_apk_end_to_end():
    sample = _first_sample()
    result = parse_apk(sample)

    assert result["status"] == "success"
    assert result["sha256"] is not None
    assert "manifest" in result
    assert result["manifest"]["package_name"] is not None
    assert isinstance(result["manifest"]["permissions"], list)
    assert "certificates" in result
    assert "assets_and_resources" in result
    assert "structural_anomalies" in result

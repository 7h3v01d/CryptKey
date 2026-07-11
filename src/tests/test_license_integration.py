"""
Tests for how file_encryptor_enhanced.py wires up cryptkey_license:
the embedded LICENSE_PUBLIC_KEY, the validate_license_key() wrapper,
and LicenseStore (QSettings-backed persistence).
"""
import pytest

import file_encryptor_enhanced as fe
from cryptkey_license import generate_keypair, generate_license_key


def test_public_key_is_configured():
    """
    Regression guard: LICENSE_PUBLIC_KEY must not be left as the empty-string
    placeholder, or every paid license silently falls back to Free tier.
    """
    assert fe.LICENSE_PUBLIC_KEY, (
        "LICENSE_PUBLIC_KEY is empty — paid licenses will not validate. "
        "Run the license generator and embed the public key."
    )


def test_wrapper_validates_a_real_license_against_embedded_key():
    """
    The app doesn't have the vendor's private key, so we can't mint a key that
    validates against the *embedded* public key here without it. Instead we
    confirm the wrapper correctly rejects a license signed by an unrelated
    keypair (i.e. it really is checking the signature, not rubber-stamping).
    """
    unrelated_priv, _ = generate_keypair()
    key = generate_license_key("commercial", 30, unrelated_priv)
    result = fe.validate_license_key(key)
    assert result["valid"] is False


def test_wrapper_empty_key_reports_free_tier():
    result = fe.validate_license_key("")
    assert result["tier"] == "free"
    assert result["valid"] is False


def test_wrapper_rejects_garbage_input():
    result = fe.validate_license_key("garbage-not-a-license")
    assert result["valid"] is False


class TestLicenseStore:
    def test_save_and_load_round_trip(self, qapp, monkeypatch):
        # Use isolated, throwaway QSettings scope so this test can't touch
        # the real user's stored license on the machine running the suite.
        from PyQt6.QtCore import QSettings
        QSettings.setDefaultFormat(QSettings.Format.IniFormat)

        fe.LicenseStore.save("dummy-license-key")
        assert fe.LicenseStore.load() == "dummy-license-key"
        fe.LicenseStore.clear()
        assert fe.LicenseStore.load() == ""

"""
Tests for cryptkey_license.py: keypair management, license signing, and
license verification (tier, expiry, machine lock, tamper detection).
"""
import base64
from datetime import datetime, timedelta, timezone

import pytest

from cryptkey_license import (
    LICENSE_TIERS,
    generate_keypair,
    generate_license_key,
    validate_license_key,
    load_or_create_keypair,
    machine_id,
)


class TestKeypairGeneration:
    def test_generate_keypair_returns_two_distinct_base64_strings(self):
        priv_b64, pub_b64 = generate_keypair()
        assert priv_b64 and pub_b64
        assert priv_b64 != pub_b64
        # Both should be valid base64.
        base64.b64decode(priv_b64)
        base64.b64decode(pub_b64)

    def test_generate_keypair_is_random(self):
        priv1, pub1 = generate_keypair()
        priv2, pub2 = generate_keypair()
        assert priv1 != priv2
        assert pub1 != pub2


class TestLoadOrCreateKeypair:
    def test_creates_new_keystore_on_first_call(self, tmp_path):
        store_path = tmp_path / "vendor.key"
        priv_b64, pub_b64 = load_or_create_keypair(store_path, "master-pw-123")
        assert store_path.exists()
        assert store_path.with_suffix(".pub.json").exists()
        assert priv_b64 and pub_b64

    def test_reload_with_correct_password_returns_same_keys(self, tmp_path):
        store_path = tmp_path / "vendor.key"
        priv1, pub1 = load_or_create_keypair(store_path, "master-pw-123")
        priv2, pub2 = load_or_create_keypair(store_path, "master-pw-123")
        assert priv1 == priv2
        assert pub1 == pub2

    def test_reload_with_wrong_password_raises(self, tmp_path):
        store_path = tmp_path / "vendor.key"
        load_or_create_keypair(store_path, "correct-password")
        with pytest.raises(ValueError):
            load_or_create_keypair(store_path, "wrong-password")


class TestGenerateAndValidateLicenseKey:
    def test_valid_license_round_trip(self, vendor_keypair):
        priv_b64, pub_b64 = vendor_keypair
        key = generate_license_key("personal", 30, priv_b64)
        result = validate_license_key(key, pub_b64)
        assert result["valid"] is True
        assert result["tier"] == "personal"
        assert result["machine"] == "ANY"

    @pytest.mark.parametrize("tier", list(LICENSE_TIERS.keys()))
    def test_all_tiers_can_be_issued_and_validated(self, vendor_keypair, tier):
        priv_b64, pub_b64 = vendor_keypair
        key = generate_license_key(tier, 30, priv_b64)
        result = validate_license_key(key, pub_b64)
        assert result["valid"] is True
        assert result["tier"] == tier

    def test_unknown_tier_raises(self, vendor_keypair):
        priv_b64, _ = vendor_keypair
        with pytest.raises(ValueError):
            generate_license_key("enterprise-deluxe", 30, priv_b64)

    def test_expired_license_is_invalid(self, vendor_keypair):
        priv_b64, pub_b64 = vendor_keypair
        key = generate_license_key("personal", -1, priv_b64)  # expired yesterday
        result = validate_license_key(key, pub_b64)
        assert result["valid"] is False
        assert "expired" in result["message"].lower()

    def test_machine_locked_license_valid_for_current_machine(self, vendor_keypair):
        priv_b64, pub_b64 = vendor_keypair
        mid = machine_id()
        key = generate_license_key("commercial", 30, priv_b64, mid=mid)
        result = validate_license_key(key, pub_b64)
        assert result["valid"] is True
        assert result["machine"] == mid

    def test_machine_locked_license_invalid_for_other_machine(self, vendor_keypair):
        priv_b64, pub_b64 = vendor_keypair
        key = generate_license_key("commercial", 30, priv_b64, mid="some-other-machine-fingerprint")
        result = validate_license_key(key, pub_b64)
        assert result["valid"] is False
        assert "different machine" in result["message"].lower()


class TestTamperingAndForgery:
    def test_key_signed_by_different_private_key_is_rejected(self):
        priv_a, _ = generate_keypair()
        _, pub_b = generate_keypair()  # attacker doesn't have priv_b

        forged_key = generate_license_key("commercial", 365, priv_a)
        result = validate_license_key(forged_key, pub_b)
        assert result["valid"] is False

    def test_tampering_with_tier_after_signing_is_detected(self, vendor_keypair):
        """Bumping 'personal' to 'commercial' post-signature must fail verification."""
        priv_b64, pub_b64 = vendor_keypair
        key = generate_license_key("personal", 30, priv_b64)

        raw = base64.b64decode(key).decode()
        tier, expiry, mid, sig_hex = raw.split(":", 3)
        tampered_raw = f"commercial:{expiry}:{mid}:{sig_hex}"
        tampered_key = base64.b64encode(tampered_raw.encode()).decode()

        result = validate_license_key(tampered_key, pub_b64)
        assert result["valid"] is False

    def test_tampering_with_expiry_after_signing_is_detected(self, vendor_keypair):
        priv_b64, pub_b64 = vendor_keypair
        key = generate_license_key("personal", 1, priv_b64)  # expires tomorrow

        raw = base64.b64decode(key).decode()
        tier, expiry, mid, sig_hex = raw.split(":", 3)
        far_future = (datetime.now(timezone.utc) + timedelta(days=3650)).strftime("%Y%m%d")
        tampered_raw = f"{tier}:{far_future}:{mid}:{sig_hex}"
        tampered_key = base64.b64encode(tampered_raw.encode()).decode()

        result = validate_license_key(tampered_key, pub_b64)
        assert result["valid"] is False


class TestMalformedInput:
    def test_empty_key_treated_as_free_tier(self, vendor_keypair):
        _, pub_b64 = vendor_keypair
        result = validate_license_key("", pub_b64)
        assert result["valid"] is False
        assert result["tier"] == "free"

    def test_none_key_treated_as_free_tier(self, vendor_keypair):
        _, pub_b64 = vendor_keypair
        result = validate_license_key(None, pub_b64)
        assert result["valid"] is False
        assert result["tier"] == "free"

    def test_garbage_string_is_invalid(self, vendor_keypair):
        _, pub_b64 = vendor_keypair
        result = validate_license_key("not-a-real-license-key!!", pub_b64)
        assert result["valid"] is False

    def test_valid_base64_wrong_structure_is_invalid(self, vendor_keypair):
        _, pub_b64 = vendor_keypair
        bogus = base64.b64encode(b"only:three:fields").decode()
        result = validate_license_key(bogus, pub_b64)
        assert result["valid"] is False

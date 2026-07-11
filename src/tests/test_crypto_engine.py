"""
Tests for CryptoEngine: encrypt_file / decrypt_file / shred_file / derive_key.
"""
import io
import logging
import os
import secrets
import zlib
from contextlib import redirect_stderr, redirect_stdout

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from file_encryptor_enhanced import SALT_SIZE, NONCE_SIZE, TAG_SIZE, setup_logging


@pytest.fixture(autouse=True, scope="module")
def _init_logging():
    setup_logging()


def _quiet(fn, *args, **kwargs):
    """Run fn while swallowing the stdout/stderr noise CryptoEngine logs on failure."""
    with redirect_stderr(io.StringIO()) as err, redirect_stdout(io.StringIO()):
        result = fn(*args, **kwargs)
    return result, err.getvalue()


class TestEncryptDecryptRoundTrip:
    def test_basic_round_trip(self, crypto, test_file, tmp_path, password, test_content):
        encrypted = tmp_path / "test.txt.enc"
        assert crypto.encrypt_file(str(test_file), str(encrypted), password, cli_mode=True)
        assert encrypted.exists()

        assert crypto.decrypt_file(str(encrypted), str(tmp_path), password, cli_mode=True)
        decrypted = tmp_path / "test.txt"
        assert decrypted.exists()
        assert decrypted.read_bytes() == test_content

    def test_round_trip_with_key_file(self, crypto, test_file, tmp_path, password, key_file, test_content):
        encrypted = tmp_path / "test.txt.enc"
        assert crypto.encrypt_file(str(test_file), str(encrypted), password, key_file=str(key_file), cli_mode=True)

        assert crypto.decrypt_file(str(encrypted), str(tmp_path), password, key_file=str(key_file), cli_mode=True)
        decrypted = tmp_path / "test.txt"
        assert decrypted.read_bytes() == test_content

    def test_decrypt_requires_matching_key_file(self, crypto, test_file, tmp_path, password, key_file):
        encrypted = tmp_path / "test.txt.enc"
        assert crypto.encrypt_file(str(test_file), str(encrypted), password, key_file=str(key_file), cli_mode=True)

        # Decrypting without the key file that was used to encrypt should fail.
        success, _ = _quiet(crypto.decrypt_file, str(encrypted), str(tmp_path), password, cli_mode=True)
        assert success is False

    def test_output_ciphertext_differs_from_plaintext(self, crypto, test_file, tmp_path, password, test_content):
        encrypted = tmp_path / "test.txt.enc"
        crypto.encrypt_file(str(test_file), str(encrypted), password, cli_mode=True)
        assert test_content not in encrypted.read_bytes()

    def test_two_encryptions_produce_different_ciphertext(self, crypto, test_file, tmp_path, password):
        """Salt/nonce must be random per-encryption, even for identical plaintext+password."""
        enc1 = tmp_path / "a.enc"
        enc2 = tmp_path / "b.enc"
        crypto.encrypt_file(str(test_file), str(enc1), password, cli_mode=True)
        crypto.encrypt_file(str(test_file), str(enc2), password, cli_mode=True)
        assert enc1.read_bytes() != enc2.read_bytes()

    def test_large_file_round_trip(self, crypto, tmp_path, password):
        big_file = tmp_path / "big.bin"
        content = os.urandom(1024 * 1024)  # 1 MB, exercises chunked hashing/compression
        big_file.write_bytes(content)
        encrypted = tmp_path / "big.bin.enc"

        assert crypto.encrypt_file(str(big_file), str(encrypted), password, cli_mode=True)
        assert crypto.decrypt_file(str(encrypted), str(tmp_path), password, cli_mode=True)
        assert (tmp_path / "big.bin").read_bytes() == content

    def test_empty_file_round_trip(self, crypto, tmp_path, password):
        empty_file = tmp_path / "empty.txt"
        empty_file.write_bytes(b"")
        encrypted = tmp_path / "empty.txt.enc"

        assert crypto.encrypt_file(str(empty_file), str(encrypted), password, cli_mode=True)
        assert crypto.decrypt_file(str(encrypted), str(tmp_path), password, cli_mode=True)
        assert (tmp_path / "empty.txt").read_bytes() == b""


class TestDecryptFailureModes:
    def test_wrong_password_fails(self, crypto, test_file, tmp_path, password):
        encrypted = tmp_path / "test.txt.enc"
        crypto.encrypt_file(str(test_file), str(encrypted), password, cli_mode=True)

        success, err = _quiet(crypto.decrypt_file, str(encrypted), str(tmp_path), "WrongPass123!", cli_mode=True)
        assert success is False, f"stderr: {err}"

    def test_invalid_short_file(self, crypto, tmp_path, password):
        bogus = tmp_path / "bogus.enc"
        bogus.write_bytes(b"INVALID")

        success, err = _quiet(crypto.decrypt_file, str(bogus), str(tmp_path), password, cli_mode=True)
        assert success is False, f"stderr: {err}"

    def test_missing_input_file(self, crypto, tmp_path, password):
        missing = tmp_path / "does_not_exist.enc"
        success, _ = _quiet(crypto.decrypt_file, str(missing), str(tmp_path), password, cli_mode=True)
        assert success is False

    def test_corrupted_ciphertext_fails_integrity_check(self, crypto, test_file, tmp_path, password):
        encrypted = tmp_path / "test.txt.enc"
        crypto.encrypt_file(str(test_file), str(encrypted), password, cli_mode=True)

        data = bytearray(encrypted.read_bytes())
        # Flip a byte roughly in the middle of the file (inside ciphertext/tag region).
        mid = len(data) // 2
        data[mid] ^= 0xFF
        encrypted.write_bytes(bytes(data))

        success, err = _quiet(crypto.decrypt_file, str(encrypted), str(tmp_path), password, cli_mode=True)
        assert success is False, f"stderr: {err}"

    def test_no_output_file_left_behind_on_failure(self, crypto, test_file, tmp_path, password):
        encrypted = tmp_path / "test.txt.enc"
        crypto.encrypt_file(str(test_file), str(encrypted), password, cli_mode=True)

        # Decrypt into a fresh, empty directory so a stray output file can only
        # mean the failure path leaked a partial/incorrect result.
        out_dir = tmp_path / "decrypt_out"
        out_dir.mkdir()
        _quiet(crypto.decrypt_file, str(encrypted), str(out_dir), "WrongPass123!", cli_mode=True)
        assert not (out_dir / "test.txt").exists()
        assert list(out_dir.iterdir()) == []


class TestLegacyFormat:
    def test_decrypt_legacy_format(self, crypto, tmp_path, password, test_content):
        salt = secrets.token_bytes(SALT_SIZE)
        nonce = secrets.token_bytes(NONCE_SIZE)
        key = crypto.derive_key(password, salt)

        encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=crypto.backend).encryptor()
        compressed = zlib.compress(test_content, level=6)
        ciphertext = encryptor.update(compressed) + encryptor.finalize()
        tag = encryptor.tag

        legacy_file = tmp_path / "legacy_test.txt.enc"
        legacy_file.write_bytes(salt + nonce + ciphertext + tag)

        expected_size = SALT_SIZE + NONCE_SIZE + len(ciphertext) + TAG_SIZE
        assert legacy_file.stat().st_size == expected_size

        success, err = _quiet(crypto.decrypt_file, str(legacy_file), str(tmp_path), password, cli_mode=True)
        assert success is True, f"stderr: {err}"

        decrypted = tmp_path / "decrypted_legacy_test.txt"
        assert decrypted.exists()
        assert decrypted.read_bytes() == test_content

    def test_legacy_file_too_short_fails(self, crypto, tmp_path, password):
        legacy_file = tmp_path / "short_legacy.enc"
        legacy_file.write_bytes(b"\x00" * (SALT_SIZE + NONCE_SIZE))  # missing ciphertext + tag

        success, _ = _quiet(crypto.decrypt_file, str(legacy_file), str(tmp_path), password, cli_mode=True)
        assert success is False


class TestDirectoryProcessing:
    def test_nested_directory_structure_preserved(self, crypto, tmp_path, password, test_content):
        sub_dir = tmp_path / "subdir"
        sub_dir.mkdir()
        sub_file = sub_dir / "subfile.txt"
        sub_file.write_bytes(test_content)

        output_dir = tmp_path / "output"
        output_file = output_dir / "subdir" / "subfile.txt.enc"

        assert crypto.encrypt_file(str(sub_file), str(output_file), password, cli_mode=True)
        assert output_file.exists()

        decrypt_out = tmp_path / "decrypted_out"
        decrypt_out.mkdir()
        assert crypto.decrypt_file(str(output_file), str(decrypt_out), password, cli_mode=True)
        assert (decrypt_out / "subfile.txt").read_bytes() == test_content


class TestShredFile:
    def test_shred_removes_file(self, crypto, test_file, tmp_path, password):
        crypto.encrypt_file(str(test_file), str(tmp_path / "test.txt.enc"), password, cli_mode=True)
        assert crypto.shred_file(str(test_file)) is True
        assert not test_file.exists()

    def test_shred_missing_file_fails_gracefully(self, crypto, tmp_path):
        missing = tmp_path / "nope.txt"
        assert crypto.shred_file(str(missing)) is False


class TestPasswordValidation:
    def test_empty_password_scores_negative(self, crypto):
        result = crypto.validate_password("")
        assert result["score"] == -1

    def test_strong_password_scores_high(self, crypto):
        result = crypto.validate_password("Tr0ub4dor&3xtraLongPhrase!")
        assert result["score"] >= 3

    def test_weak_password_scores_low(self, crypto):
        result = crypto.validate_password("password")
        assert result["score"] < 3


class TestDeriveKey:
    def test_same_inputs_produce_same_key(self, crypto, password):
        salt = secrets.token_bytes(SALT_SIZE)
        k1 = crypto.derive_key(password, salt)
        k2 = crypto.derive_key(password, salt)
        assert k1 == k2

    def test_different_salt_produces_different_key(self, crypto, password):
        k1 = crypto.derive_key(password, secrets.token_bytes(SALT_SIZE))
        k2 = crypto.derive_key(password, secrets.token_bytes(SALT_SIZE))
        assert k1 != k2

    def test_key_file_changes_derived_key(self, crypto, password, key_file):
        salt = secrets.token_bytes(SALT_SIZE)
        k_without = crypto.derive_key(password, salt)
        k_with = crypto.derive_key(password, salt, key_file=str(key_file))
        assert k_without != k_with

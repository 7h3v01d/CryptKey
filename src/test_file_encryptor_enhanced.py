import unittest
import os
import tempfile
import shutil
import io
import secrets
import zlib
import logging
from contextlib import redirect_stderr, redirect_stdout
from file_encryptor_enhanced import CryptoEngine, setup_logging, SALT_SIZE, NONCE_SIZE, TAG_SIZE
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class TestCryptoEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        setup_logging()

    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.crypto = CryptoEngine()
        self.test_file = os.path.join(self.temp_dir, "test.txt")
        self.encrypted_file = os.path.join(self.temp_dir, "test.txt.enc")
        self.decrypted_file = os.path.join(self.temp_dir, "test.txt")  # Matches original_filename in metadata
        self.key_file = os.path.join(self.temp_dir, "key.bin")
        self.password = "SecurePass123!"
        self.test_content = b"Hello, this is a test file!"
        self.legacy_encrypted_file = os.path.join(self.temp_dir, "legacy_test.txt.enc")

        with open(self.test_file, 'wb') as f:
            f.write(self.test_content)
        with open(self.key_file, 'wb') as f:
            f.write(b"key_data")

    def tearDown(self):
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_encrypt_decrypt(self):
        # Test encryption
        success = self.crypto.encrypt_file(self.test_file, self.encrypted_file, self.password, cli_mode=True)
        self.assertTrue(success, "Encryption should succeed")
        self.assertTrue(os.path.exists(self.encrypted_file), "Encrypted file should exist")

        # Test decryption
        success = self.crypto.decrypt_file(self.encrypted_file, self.temp_dir, self.password, cli_mode=True)
        self.assertTrue(success, "Decryption should succeed")
        self.assertTrue(os.path.exists(self.decrypted_file), "Decrypted file should exist")

        # Verify content
        with open(self.decrypted_file, 'rb') as f:
            decrypted_content = f.read()
        self.assertEqual(self.test_content, decrypted_content, "Decrypted content should match original")

    def test_encrypt_decrypt_with_key_file(self):
        # Test encryption with key file
        success = self.crypto.encrypt_file(self.test_file, self.encrypted_file, self.password, key_file=self.key_file, cli_mode=True)
        self.assertTrue(success, "Encryption with key file should succeed")
        self.assertTrue(os.path.exists(self.encrypted_file), "Encrypted file should exist")

        # Test decryption with key file
        success = self.crypto.decrypt_file(self.encrypted_file, self.temp_dir, self.password, key_file=self.key_file, cli_mode=True)
        self.assertTrue(success, "Decryption with key file should succeed")
        self.assertTrue(os.path.exists(self.decrypted_file), "Decrypted file should exist")

        # Verify content
        with open(self.decrypted_file, 'rb') as f:
            decrypted_content = f.read()
        self.assertEqual(self.test_content, decrypted_content, "Decrypted content should match original")

    def test_decrypt_wrong_password(self):
        # Test encryption
        success = self.crypto.encrypt_file(self.test_file, self.encrypted_file, self.password, cli_mode=True)
        self.assertTrue(success, "Encryption should succeed")

        # Test decryption with wrong password
        with redirect_stderr(io.StringIO()) as stderr, redirect_stdout(io.StringIO()):
            success = self.crypto.decrypt_file(self.encrypted_file, self.temp_dir, "WrongPass123!", cli_mode=True)
            stderr_output = stderr.getvalue()
        self.assertFalse(success, f"Decryption with wrong password should fail. Stderr: {stderr_output}")

    def test_invalid_file_format(self):
        # Create an invalid file (too short)
        with open(self.encrypted_file, 'wb') as f:
            f.write(b"INVALID")
        
        with redirect_stderr(io.StringIO()) as stderr, redirect_stdout(io.StringIO()):
            success = self.crypto.decrypt_file(self.encrypted_file, self.temp_dir, self.password, cli_mode=True)
            stderr_output = stderr.getvalue()
        self.assertFalse(success, f"Decryption of invalid file should fail. Stderr: {stderr_output}")

    def test_directory_processing(self):
        # Create a directory structure
        sub_dir = os.path.join(self.temp_dir, "subdir")
        os.makedirs(sub_dir)
        sub_file = os.path.join(sub_dir, "subfile.txt")
        with open(sub_file, 'wb') as f:
            f.write(self.test_content)

        output_dir = os.path.join(self.temp_dir, "output")
        os.makedirs(output_dir)

        # Encrypt directory
        files_to_process = [sub_dir]
        base_paths = {sub_file: sub_dir}
        success_count = 0
        for input_file in [sub_file]:
            output_file = os.path.join(output_dir, "subdir", "subfile.txt.enc")
            success = self.crypto.encrypt_file(input_file, output_file, self.password, key_file=self.key_file, cli_mode=True)
            if success:
                success_count += 1
        self.assertEqual(success_count, 1, "Directory encryption should succeed")
        self.assertTrue(os.path.exists(os.path.join(output_dir, "subdir", "subfile.txt.enc")), "Encrypted file should exist")

    def test_shred_file(self):
        self.crypto.encrypt_file(self.test_file, self.encrypted_file, self.password, cli_mode=True)
        success = self.crypto.shred_file(self.test_file)
        self.assertTrue(success, "Shredding should succeed")
        self.assertFalse(os.path.exists(self.test_file), "Shredded file should not exist")

    def test_decrypt_legacy_format(self):
        try:
            # Simulate legacy encryption (no magic number, no metadata, with zlib compression)
            salt = secrets.token_bytes(SALT_SIZE)
            nonce = secrets.token_bytes(NONCE_SIZE)
            key = self.crypto.derive_key(self.password, salt)
            encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.crypto.backend).encryptor()
            compressor = zlib.compressobj(level=6)
            compressed = compressor.compress(self.test_content) + compressor.flush()
            ciphertext = encryptor.update(compressed) + encryptor.finalize()
            tag = encryptor.tag
            with open(self.legacy_encrypted_file, 'wb') as f_out:
                f_out.write(salt)
                f_out.write(nonce)
                f_out.write(ciphertext)
                f_out.write(tag)
            
            # Verify file size
            file_size = os.path.getsize(self.legacy_encrypted_file)
            expected_size = SALT_SIZE + NONCE_SIZE + len(ciphertext) + TAG_SIZE
            self.assertEqual(file_size, expected_size, f"Legacy file size mismatch: got {file_size}, expected {expected_size}")

            # Log file content for debugging
            with open(self.legacy_encrypted_file, 'rb') as f:
                content = f.read()
                logging.info(f"Legacy file content (hex): {content.hex()}")

            # Test decryption
            with redirect_stderr(io.StringIO()) as stderr, redirect_stdout(io.StringIO()):
                success = self.crypto.decrypt_file(self.legacy_encrypted_file, self.temp_dir, self.password, cli_mode=True)
                stderr_output = stderr.getvalue()
            self.assertTrue(success, f"Legacy decryption should succeed. Stderr: {stderr_output}")
            self.assertTrue(os.path.exists(os.path.join(self.temp_dir, "decrypted_legacy_test.txt")), "Decrypted legacy file should exist")
            with open(os.path.join(self.temp_dir, "decrypted_legacy_test.txt"), 'rb') as f:
                decrypted_content = f.read()
            self.assertEqual(self.test_content, decrypted_content, "Decrypted legacy content should match original")
        except Exception as e:
            self.fail(f"Legacy decryption test setup failed: {e}")

if __name__ == '__main__':
    unittest.main()
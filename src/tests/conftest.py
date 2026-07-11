"""
Shared pytest fixtures for the CryptKey test suite.
"""
import os
import sys
from pathlib import Path

import pytest

# Make sure the app package (one directory up from tests/) is importable,
# regardless of where pytest is invoked from.
SRC_DIR = str(Path(__file__).resolve().parent.parent)
if SRC_DIR not in sys.path:
    sys.path.insert(0, SRC_DIR)

# PyQt6 needs a display. Force the offscreen platform plugin so the suite
# runs headless (CI, containers, etc.) without needing a real X server.
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")


@pytest.fixture(scope="session")
def qapp():
    """A single QApplication instance shared across tests that need Qt."""
    from PyQt6.QtWidgets import QApplication
    app = QApplication.instance() or QApplication(sys.argv)
    yield app


@pytest.fixture()
def password():
    return "SecurePass123!"


@pytest.fixture()
def test_content():
    return b"Hello, this is a test file!"


@pytest.fixture()
def test_file(tmp_path, test_content):
    path = tmp_path / "test.txt"
    path.write_bytes(test_content)
    return path


@pytest.fixture()
def key_file(tmp_path):
    path = tmp_path / "key.bin"
    path.write_bytes(b"key_data")
    return path


@pytest.fixture()
def crypto():
    from file_encryptor_enhanced import CryptoEngine
    return CryptoEngine()


@pytest.fixture()
def vendor_keypair():
    """A fresh, in-memory Ed25519 keypair (private_b64, public_b64)."""
    from cryptkey_license import generate_keypair
    return generate_keypair()

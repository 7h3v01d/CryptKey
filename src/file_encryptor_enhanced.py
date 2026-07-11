"""
CryptKey v2.1.0 – Secure File & Directory Encryptor
Author  : Leon Priest <leonpriest76@gmail.com>
License : See LicenseManager for commercial / MIT details
"""

import sys
import os
import zlib
import logging
import secrets
import argparse
import string
import json
import getpass
import traceback
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional, Dict, Any, Callable

from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QPushButton, QFileDialog, QLineEdit, QLabel, QProgressBar,
    QMessageBox, QRadioButton, QGroupBox, QCheckBox,
    QListWidget, QMenu, QTextEdit, QFrame,
    QDialog, QSizePolicy, QStackedWidget
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings, QTimer
from PyQt6.QtGui import (
    QDragEnterEvent, QDropEvent, QIcon, QPixmap, QImage, QFont,
    QColor, QPalette, QPainter, QLinearGradient, QBrush, QPen
)
from argon2 import PasswordHasher, low_level
from argon2.exceptions import HashingError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from zxcvbn import zxcvbn
from tqdm import tqdm


def resource_path(relative_path: str) -> str:
    """
    Resolve a path to a bundled resource (e.g. icon.ico) that works both
    when running from source and when frozen into a PyInstaller onefile
    executable (which unpacks data files to a temp dir at sys._MEIPASS).
    """
    base_path = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base_path, relative_path)


# ─────────────────────────────────────────────────────────
#  DESIGN TOKENS
# ─────────────────────────────────────────────────────────
C = {
    "bg":          "#0D0F14",
    "surface":     "#141720",
    "surface2":    "#1C2030",
    "border":      "#252A3A",
    "accent":      "#00E5FF",
    "accent_dim":  "#009AB5",
    "green":       "#00FFB2",
    "yellow":      "#FFD166",
    "red":         "#FF4D6D",
    "text":        "#E8EDF5",
    "text_dim":    "#7A8499",
    "text_xdim":   "#3E4559",
}

STYLESHEET = f"""
QWidget {{
    color: {C['text']};
    font-family: 'Segoe UI', 'SF Pro Display', 'Helvetica Neue', Arial, sans-serif;
    font-size: 13px;
}}
QMainWindow {{ background-color: {C['bg']}; }}
QLabel, QCheckBox, QRadioButton {{ background: transparent; }}
QTabWidget::pane {{
    border: 1px solid {C['border']};
    border-radius: 8px;
    background: {C['surface']};
    margin-top: -1px;
}}
QTabBar::tab {{
    background: transparent; color: {C['text_dim']};
    padding: 10px 22px; border: none;
    font-size: 13px; font-weight: 500; letter-spacing: 0.5px;
}}
QTabBar::tab:selected {{ color: {C['accent']}; border-bottom: 2px solid {C['accent']}; }}
QTabBar::tab:hover:!selected {{ color: {C['text']}; }}
QGroupBox {{
    background: {C['surface']}; border: 1px solid {C['border']};
    border-radius: 8px; margin-top: 18px;
    padding: 12px 10px 10px 10px;
    font-weight: 600; font-size: 11px; letter-spacing: 0.8px; color: {C['text_dim']};
}}
QGroupBox::title {{
    subcontrol-origin: margin; subcontrol-position: top left;
    left: 12px; padding: 0 6px;
    background: {C['surface']}; color: {C['text_dim']};
}}
QPushButton {{
    background: {C['surface2']}; color: {C['text']};
    border: 1px solid {C['border']}; border-radius: 6px;
    padding: 8px 18px; font-weight: 500; font-size: 13px;
}}
QPushButton:hover {{
    background: {C['border']}; border-color: {C['accent_dim']}; color: {C['accent']};
}}
QPushButton:pressed {{ background: {C['surface']}; }}
QPushButton:disabled {{ color: {C['text_xdim']}; border-color: {C['text_xdim']}; background: {C['surface']}; }}
QPushButton#primary {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 {C['accent']}, stop:1 {C['accent_dim']});
    color: #000; border: none; font-weight: 700;
    font-size: 14px; padding: 10px 28px; border-radius: 8px; letter-spacing: 0.5px;
}}
QPushButton#primary:hover {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 #33ECFF, stop:1 {C['accent']}); color: #000;
}}
QPushButton#primary:disabled {{ background: {C['surface2']}; color: {C['text_xdim']}; }}
QPushButton#danger {{
    background: transparent; color: {C['red']}; border: 1px solid {C['red']};
}}
QPushButton#danger:hover {{ background: rgba(255,77,109,0.12); }}
QLineEdit {{
    background: {C['surface2']}; border: 1px solid {C['border']};
    border-radius: 6px; padding: 8px 12px; color: {C['text']};
    selection-background-color: {C['accent']}; selection-color: #000;
}}
QLineEdit:focus {{ border: 1px solid {C['accent']}; background: {C['surface']}; }}
QListWidget {{
    background: {C['surface2']}; border: 1px solid {C['border']};
    border-radius: 8px; padding: 6px; color: {C['text']}; outline: none;
}}
QListWidget::item {{ padding: 7px 10px; border-radius: 4px; margin: 1px 0; }}
QListWidget::item:hover {{ background: {C['border']}; }}
QListWidget::item:selected {{ background: rgba(0,229,255,0.12); color: {C['accent']}; }}
QProgressBar {{
    background: {C['surface2']}; border: 1px solid {C['border']};
    border-radius: 5px; height: 8px; color: transparent;
}}
QProgressBar::chunk {{
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
        stop:0 {C['accent']}, stop:1 {C['green']}); border-radius: 5px;
}}
QCheckBox {{ spacing: 8px; color: {C['text']}; }}
QCheckBox::indicator {{
    width: 18px; height: 18px; border: 1px solid {C['border']};
    border-radius: 4px; background: {C['surface2']};
}}
QCheckBox::indicator:checked {{ background: {C['accent']}; border-color: {C['accent']}; }}
QRadioButton {{ spacing: 8px; color: {C['text']}; }}
QRadioButton::indicator {{
    width: 18px; height: 18px; border: 1px solid {C['border']};
    border-radius: 9px; background: {C['surface2']};
}}
QRadioButton::indicator:checked {{ background: {C['accent']}; border-color: {C['accent']}; }}
QTextEdit {{
    background: {C['surface2']}; border: 1px solid {C['border']};
    border-radius: 6px; padding: 8px; color: {C['text_dim']};
    font-family: 'Cascadia Code','JetBrains Mono','Courier New',monospace; font-size: 11px;
}}
QScrollBar:vertical {{
    background: {C['surface']}; width: 8px; border-radius: 4px;
}}
QScrollBar::handle:vertical {{
    background: {C['border']}; border-radius: 4px; min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {C['accent_dim']}; }}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
QMenu {{
    background: {C['surface2']}; border: 1px solid {C['border']};
    border-radius: 6px; padding: 4px;
}}
QMenu::item {{ padding: 7px 20px; border-radius: 4px; }}
QMenu::item:selected {{ background: rgba(0,229,255,0.12); color: {C['accent']}; }}
QDialog {{ background: {C['surface']}; border: 1px solid {C['border']}; }}
QFrame[frameShape="4"], QFrame[frameShape="5"] {{
    color: {C['border']}; background: {C['border']}; border: none; max-height: 1px;
}}
"""

# ─────────────────────────────────────────────────────────
#  LOGGING
# ─────────────────────────────────────────────────────────
LOG_FILE_PATH = None

def setup_logging():
    global LOG_FILE_PATH
    if logging.getLogger().hasHandlers():
        return
    try:
        if sys.platform == "win32":
            log_dir = Path(os.getenv('APPDATA', Path.home())) / "CryptKey"
        else:
            log_dir = Path.home() / ".local/share/CryptKey"
        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / 'cryptkey.log'
        logging.basicConfig(
            filename=log_file, level=logging.INFO,
            format='%(asctime)s [%(levelname)s] %(message)s', force=True)
        LOG_FILE_PATH = str(log_file)
        logging.info("── CryptKey v2.1.0 started ──")
        return log_file
    except Exception as e:
        logging.basicConfig(level=logging.INFO,
                            format='%(asctime)s [%(levelname)s] %(message)s', force=True)
        logging.error(f"File logging setup failed: {e}")

# ─────────────────────────────────────────────────────────
#  LICENSE MANAGER  (Ed25519 – uses shared cryptkey_license module)
# ─────────────────────────────────────────────────────────
from cryptkey_license import (
    LICENSE_TIERS,
    machine_id as _machine_id,
    validate_license_key as _validate_license_key_raw,
)

# ── Embed your public key here ───────────────────────────
# Run the license generator, click "Show Public Key", and
# paste the constant it gives you below.
# Until you do, the app runs in Free tier for everyone.
LICENSE_PUBLIC_KEY = "LS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUNvd0JRWURLMlZ3QXlFQWtxTTlTNXprSUtIU3cyQXZyeldLS25BUERyaC9GaFplcXNabmFtSENoNlU9Ci0tLS0tRU5EIFBVQkxJQyBLRVktLS0tLQo="


def validate_license_key(key_str: str) -> Dict[str, Any]:
    """Wrapper: injects the embedded public key automatically."""
    if not LICENSE_PUBLIC_KEY:
        # No public key embedded yet — accept no paid keys,
        # treat everyone as Free (safe fallback during development).
        if not key_str:
            return {"valid": False, "tier": "free", "expiry": None,
                    "message": "No license key – running as Free tier."}
        return {"valid": False, "tier": "free", "expiry": None,
                "message": "⚠ App not configured: LICENSE_PUBLIC_KEY is empty. "
                           "Embed your public key to enable license verification."}
    return _validate_license_key_raw(key_str, LICENSE_PUBLIC_KEY)


class LicenseStore:
    @staticmethod
    def load() -> str:
        return QSettings("CryptKey", "License").value("license_key", "")

    @staticmethod
    def save(key_str: str):
        QSettings("CryptKey", "License").setValue("license_key", key_str)

    @staticmethod
    def clear():
        QSettings("CryptKey", "License").remove("license_key")


# ─────────────────────────────────────────────────────────
#  CRYPTO ENGINE
# ─────────────────────────────────────────────────────────
MAGIC_NUMBER = b'ENC1'
MAGIC_SIZE = 4
CHUNK_SIZE = 8192
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
HEADER_LEN_SIZE = 4
KEY_LEN = 32
INVALID_MAGIC_NUMBERS = {b'INVA'}


class CryptoEngine:
    def __init__(self):
        self.backend = default_backend()
        self.ph = PasswordHasher(time_cost=4, memory_cost=2 ** 17, parallelism=8)

    def derive_key(self, password: str, salt: bytes, key_file: Optional[str] = None) -> bytes:
        try:
            secret = password.encode('utf-8')
            if key_file and os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    key_data = f.read(1024)
                digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
                digest.update(key_data)
                secret += digest.finalize()
            return low_level.hash_secret_raw(
                secret=secret, salt=salt,
                time_cost=self.ph.time_cost, memory_cost=self.ph.memory_cost,
                parallelism=self.ph.parallelism,
                hash_len=KEY_LEN, type=low_level.Type.ID)
        except HashingError as e:
            raise ValueError("Key derivation failed.")

    @staticmethod
    def validate_password(password: str) -> Dict[str, Any]:
        if not password:
            return {'score': -1, 'feedback': {'warning': 'Password cannot be empty.'}}
        return zxcvbn(password)

    def _cleanup(self, path: str):
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except OSError:
                pass

    def shred_file(self, file_path: str, passes: int = 3) -> bool:
        try:
            file_size = os.path.getsize(file_path)
            with open(file_path, 'r+b') as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
            os.remove(file_path)
            logging.info(f"Shredded: {file_path}")
            return True
        except Exception as e:
            logging.error(f"Shred failed: {e}")
            return False

    def encrypt_file(self, input_path: str, output_path: str, password: str,
                     key_file: Optional[str] = None,
                     progress_callback=None, status_signal=None,
                     cancel_flag: Optional[List[bool]] = None,
                     cli_mode: bool = False) -> bool:
        try:
            os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
            salt, nonce = secrets.token_bytes(SALT_SIZE), secrets.token_bytes(NONCE_SIZE)
            key = self.derive_key(password, salt, key_file)
            digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
            with open(input_path, 'rb') as f_in:
                while chunk := f_in.read(CHUNK_SIZE):
                    digest.update(chunk)
            metadata = {'original_filename': os.path.basename(input_path),
                        'sha256': digest.finalize().hex()}
            header_bytes = json.dumps(metadata).encode('utf-8')
            header_len_bytes = len(header_bytes).to_bytes(HEADER_LEN_SIZE, 'big')
            encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.backend).encryptor()
            total_size = os.path.getsize(input_path)
            processed_bytes = 0
            last_progress = -1
            pbar = tqdm(total=total_size, unit="B", unit_scale=True,
                        desc=f"Encrypting {os.path.basename(input_path)}", leave=False) if cli_mode else None
            with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
                f_out.write(MAGIC_NUMBER)
                f_out.write(salt)
                f_out.write(nonce)
                f_out.write(header_len_bytes)
                f_out.write(encryptor.update(header_bytes))
                compressor = zlib.compressobj()
                while True:
                    if cancel_flag and cancel_flag[0]:
                        raise InterruptedError("Cancelled.")
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk:
                        break
                    cc = compressor.compress(chunk)
                    if cc:
                        f_out.write(encryptor.update(cc))
                    processed_bytes += len(chunk)
                    if pbar:
                        pbar.update(len(chunk))
                    if progress_callback and total_size >= 1048576:
                        p = int((processed_bytes / total_size) * 100)
                        if p > last_progress:
                            progress_callback(p)
                            last_progress = p
                rc = compressor.flush()
                if rc:
                    f_out.write(encryptor.update(rc))
                f_out.write(encryptor.finalize())
                f_out.write(encryptor.tag)
                f_out.flush()
                os.fsync(f_out.fileno())
            if pbar:
                pbar.close()
            logging.info(f"Encrypted: {input_path} -> {output_path}")
            if status_signal:
                status_signal.emit(f"✓ Encrypted: {os.path.basename(input_path)}")
            return True
        except Exception as e:
            self._cleanup(output_path)
            msg = f"Encryption failed for {os.path.basename(input_path)}: {e}"
            logging.error(msg + f"\n{traceback.format_exc()}")
            if status_signal:
                status_signal.emit(f"✗ {msg}")
            if cli_mode:
                print(f"ERROR: {msg}")
            return False

    def decrypt_file(self, input_path: str, output_dir: str, password: str,
                     key_file: Optional[str] = None,
                     progress_callback=None, status_signal=None,
                     cancel_flag: Optional[List[bool]] = None,
                     cli_mode: bool = False) -> bool:
        output_path = None
        for attempt in range(3):
            try:
                file_size = os.path.getsize(input_path)
                if file_size < MAGIC_SIZE:
                    raise ValueError("File too short.")
                with open(input_path, 'rb') as f_in:
                    magic = f_in.read(MAGIC_SIZE)
                    if magic in INVALID_MAGIC_NUMBERS:
                        raise ValueError(f"Unsupported format: {magic!r}")
                    if magic != MAGIC_NUMBER:
                        # Legacy format
                        exp_legacy = SALT_SIZE + NONCE_SIZE + TAG_SIZE + 1
                        if file_size < exp_legacy:
                            raise ValueError("File too short for legacy decryption.")
                        f_in.seek(0)
                        salt = f_in.read(SALT_SIZE)
                        nonce = f_in.read(NONCE_SIZE)
                        remaining_size = file_size - SALT_SIZE - NONCE_SIZE - TAG_SIZE
                        key = self.derive_key(password, salt, key_file)
                        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce),
                                           backend=self.backend).decryptor()
                        output_path = os.path.join(output_dir,
                            f"decrypted_{os.path.basename(input_path).replace('.enc', '')}")
                        with open(output_path, 'wb') as f_out:
                            ct = f_in.read(remaining_size)
                            tag = f_in.read(TAG_SIZE)
                            decrypted = decryptor.update(ct) + decryptor.finalize_with_tag(tag)
                            f_out.write(zlib.decompress(decrypted))
                            f_out.flush()
                            os.fsync(f_out.fileno())
                        if status_signal:
                            status_signal.emit(f"✓ Decrypted (legacy): {os.path.basename(output_path)}")
                        return True
                    # New format
                    salt = f_in.read(SALT_SIZE)
                    nonce = f_in.read(NONCE_SIZE)
                    header_len_bytes = f_in.read(HEADER_LEN_SIZE)
                    header_len = int.from_bytes(header_len_bytes, 'big')
                    key = self.derive_key(password, salt, key_file)
                    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce),
                                       backend=self.backend).decryptor()
                    encrypted_header = f_in.read(header_len)
                    total_size = file_size - (MAGIC_SIZE + SALT_SIZE + NONCE_SIZE +
                                              HEADER_LEN_SIZE + header_len + TAG_SIZE)
                    ciphertext = f_in.read(total_size)
                    tag = f_in.read(TAG_SIZE)
                    try:
                        decrypted_data = (decryptor.update(encrypted_header + ciphertext) +
                                          decryptor.finalize_with_tag(tag))
                    except InvalidTag as e:
                        if attempt < 2:
                            time.sleep(0.1)
                            continue
                        raise ValueError("Wrong password or corrupted file.") from e
                    header_json = decrypted_data[:header_len]
                    decrypted_ct = decrypted_data[header_len:]
                    try:
                        metadata = json.loads(header_json.decode('utf-8'))
                    except Exception as e:
                        raise ValueError(f"Corrupted header: {e}")
                    original_filename = metadata.get('original_filename',
                        os.path.basename(input_path).replace('.enc', ''))
                    output_path = os.path.join(output_dir, original_filename)
                    os.makedirs(os.path.dirname(output_path) or '.', exist_ok=True)
                    with open(output_path, 'wb') as f_out:
                        dec = zlib.decompressobj()
                        chunk = dec.decompress(decrypted_ct)
                        if chunk:
                            f_out.write(chunk)
                        rest = dec.flush()
                        if rest:
                            f_out.write(rest)
                        f_out.flush()
                        os.fsync(f_out.fileno())
                    # Integrity
                    digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
                    with open(output_path, 'rb') as chk:
                        while chunk := chk.read(CHUNK_SIZE):
                            digest.update(chunk)
                    if digest.finalize().hex() != metadata.get('sha256'):
                        self._cleanup(output_path)
                        raise ValueError("SHA-256 checksum mismatch.")
                    logging.info(f"Decrypted: {input_path} -> {output_path}")
                    if status_signal:
                        status_signal.emit(f"✓ Decrypted: {os.path.basename(output_path)}")
                    return True
            except Exception as e:
                if output_path:
                    self._cleanup(output_path)
                msg = f"Decryption failed for {os.path.basename(input_path)}: {e}"
                logging.error(msg + f"\n{traceback.format_exc()}")
                if status_signal:
                    status_signal.emit(f"✗ {msg}")
                if cli_mode:
                    print(f"ERROR: {msg}")
                return False
        return False


# ─────────────────────────────────────────────────────────
#  WORKER THREAD
# ─────────────────────────────────────────────────────────
class WorkerThread(QThread):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal(int, int)

    def __init__(self, crypto, operation, input_paths, output_dir, password, key_file, shred):
        super().__init__()
        self.crypto = crypto
        self.operation = operation
        self.input_paths = input_paths
        self.output_dir = output_dir
        self.password = password
        self.key_file = key_file
        self.shred = shred
        self.cancel_flag = [False]

    def run(self):
        success = 0
        total = len(self.input_paths)
        for i, input_path in enumerate(self.input_paths):
            if self.cancel_flag[0]:
                break
            rel_path = os.path.basename(input_path)
            output_path = os.path.join(self.output_dir,
                rel_path + ('.enc' if self.operation == 'encrypt' else ''))
            if self.operation == 'encrypt':
                ok = self.crypto.encrypt_file(
                    input_path, output_path, self.password, self.key_file,
                    progress_callback=self.progress.emit,
                    status_signal=self.status,
                    cancel_flag=self.cancel_flag)
                if ok and self.shred:
                    self.crypto.shred_file(input_path)
            else:
                ok = self.crypto.decrypt_file(
                    input_path, self.output_dir, self.password, self.key_file,
                    progress_callback=self.progress.emit,
                    status_signal=self.status,
                    cancel_flag=self.cancel_flag)
            if ok:
                success += 1
            self.progress.emit(int((i + 1) / total * 100))
        self.finished.emit(success, total)


# ─────────────────────────────────────────────────────────
#  DROP ZONE LIST
# ─────────────────────────────────────────────────────────
class DropZoneList(QListWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setAcceptDrops(True)
        self.setMinimumHeight(130)
        self.hint = QLabel("Drop files or folders here, or use the buttons below", self)
        self.hint.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.hint.setStyleSheet(
            f"color:{C['text_xdim']};font-size:12px;background:transparent;border:none;")
        self._update_hint()

    def _position_hint(self):
        self.hint.setGeometry(0, 0, self.width(), self.height())

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._position_hint()

    def _update_hint(self):
        self.hint.setVisible(self.count() == 0)

    def addItem(self, item):
        super().addItem(item)
        self._update_hint()

    def takeItem(self, row):
        item = super().takeItem(row)
        self._update_hint()
        return item

    def clear(self):
        super().clear()
        self._update_hint()

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if os.path.exists(path):
                self.addItem(path)


# ─────────────────────────────────────────────────────────
#  HEADER BANNER
# ─────────────────────────────────────────────────────────
class HeaderBanner(QWidget):
    def __init__(self, license_info: dict, parent=None):
        super().__init__(parent)
        self.setFixedHeight(62)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(20, 0, 20, 0)

        logo = QLabel("<b>⚿ CryptKey</b>")
        logo.setStyleSheet(f"font-size:19px;color:{C['accent']};letter-spacing:1px;")
        logo.setTextFormat(Qt.TextFormat.RichText)
        layout.addWidget(logo)

        ver = QLabel("v2.1")
        ver.setStyleSheet(f"font-size:11px;color:{C['text_xdim']};margin-left:4px;margin-top:7px;")
        layout.addWidget(ver)

        layout.addStretch()

        self.tier_badge = QLabel()
        self._update_badge(license_info)
        layout.addWidget(self.tier_badge)

    def _update_badge(self, info: dict):
        tier = info.get("tier", "free")
        caps = LICENSE_TIERS.get(tier, LICENSE_TIERS["free"])
        label = caps["label"].upper()
        if info.get("valid") and tier != "free":
            bg, fg = C['accent'], "#000"
        elif tier == "free":
            bg, fg = C['surface2'], C['text_dim']
        else:
            bg, fg = C['red'], "#fff"
        self.tier_badge.setText(f"  {label}  ")
        self.tier_badge.setStyleSheet(
            f"background:{bg};color:{fg};border-radius:10px;"
            f"font-size:10px;font-weight:700;letter-spacing:1px;padding:3px 8px;")

    def refresh(self, info: dict):
        self._update_badge(info)

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        grad = QLinearGradient(0, 0, self.width(), 0)
        grad.setColorAt(0, QColor(C['surface']))
        grad.setColorAt(1, QColor(C['bg']))
        painter.fillRect(self.rect(), QBrush(grad))
        painter.setPen(QPen(QColor(C['border']), 1))
        painter.drawLine(0, self.height() - 1, self.width(), self.height() - 1)


# ─────────────────────────────────────────────────────────
#  MAIN WINDOW
# ─────────────────────────────────────────────────────────
class FileEncryptor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.crypto = CryptoEngine()
        self.cancel_flag = [False]
        self.thread = None

        self._license_info = validate_license_key(LicenseStore.load())
        self._license_caps = LICENSE_TIERS.get(
            self._license_info.get("tier", "free"), LICENSE_TIERS["free"])

        self.setWindowTitle("CryptKey 2.1 – Secure File Encryptor")
        self.setWindowIcon(QIcon(resource_path("icon.ico")))
        self.setMinimumSize(820, 660)
        self.resize(920, 700)

        self._init_ui()
        self._load_settings()
        self._apply_license_ui()

    def _init_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # Header
        self.header = HeaderBanner(self._license_info)
        root_layout.addWidget(self.header)

        # Body
        body = QWidget()
        body_layout = QHBoxLayout(body)
        body_layout.setContentsMargins(0, 0, 0, 0)
        body_layout.setSpacing(0)

        # Sidebar
        sidebar = QWidget()
        sidebar.setFixedWidth(190)
        sidebar.setStyleSheet(
            f"background:{C['surface']};border-right:1px solid {C['border']};")
        sb_layout = QVBoxLayout(sidebar)
        sb_layout.setContentsMargins(10, 16, 10, 16)
        sb_layout.setSpacing(4)

        self._nav_btns: Dict[str, QPushButton] = {}
        nav_items = [
            ("🔒  Encrypt / Decrypt", "main"),
            ("📋  Activity Log",      "logs"),
            ("⚿  License",           "license"),
            ("ℹ  About",             "about"),
        ]
        for label, key in nav_items:
            btn = QPushButton(label)
            btn.setCheckable(True)
            btn.setStyleSheet(f"""
                QPushButton {{
                    text-align:left; padding:10px 14px; border:none;
                    border-radius:6px; background:transparent;
                    color:{C['text_dim']}; font-size:13px; font-weight:500;
                }}
                QPushButton:checked {{
                    background:rgba(0,229,255,0.10); color:{C['accent']};
                    border-left:3px solid {C['accent']};
                }}
                QPushButton:hover:!checked {{
                    background:{C['border']}; color:{C['text']};
                }}
            """)
            btn.clicked.connect(lambda _, k=key: self._switch_page(k))
            sb_layout.addWidget(btn)
            self._nav_btns[key] = btn

        sb_layout.addStretch()

        lic_quick = QPushButton("⚿  Manage License")
        lic_quick.setStyleSheet(f"""
            QPushButton {{
                text-align:left; padding:9px 14px; border-radius:6px;
                border:1px solid {C['border']}; background:{C['surface2']};
                color:{C['text_dim']}; font-size:12px;
            }}
            QPushButton:hover {{ color:{C['accent']}; border-color:{C['accent_dim']}; }}
        """)
        lic_quick.clicked.connect(lambda: self._switch_page("license"))
        sb_layout.addWidget(lic_quick)

        body_layout.addWidget(sidebar)

        # Pages
        self.stack = QStackedWidget()
        self.stack.setStyleSheet(f"background:{C['bg']};")
        body_layout.addWidget(self.stack)

        self.stack.addWidget(self._build_main_page())    # 0
        self.stack.addWidget(self._build_logs_page())    # 1
        self.stack.addWidget(self._build_license_page()) # 2
        self.stack.addWidget(self._build_about_page())   # 3
        self._page_index = {"main": 0, "logs": 1, "license": 2, "about": 3}

        root_layout.addWidget(body)

        # Status bar
        self.status_bar = QLabel("  Ready")
        self.status_bar.setFixedHeight(26)
        self.status_bar.setStyleSheet(
            f"background:{C['surface']};color:{C['text_dim']};"
            f"font-size:11px;border-top:1px solid {C['border']};padding-left:12px;")
        root_layout.addWidget(self.status_bar)

        self._switch_page("main")

    # ── Page builders ──────────────────────────────────────

    def _build_main_page(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(14)

        # Files
        file_grp = QGroupBox("FILES")
        fl = QVBoxLayout(file_grp)
        fl.setSpacing(8)
        self.file_list = DropZoneList()
        self.file_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_list.customContextMenuRequested.connect(self._ctx_menu)
        fl.addWidget(self.file_list)
        btn_row = QHBoxLayout()
        btn_row.setSpacing(8)
        for label, slot in [("＋ Add Files", self._add_files), ("📁 Add Folder", self._add_folder)]:
            b = QPushButton(label)
            b.clicked.connect(slot)
            btn_row.addWidget(b)
        btn_row.addStretch()
        clr = QPushButton("✕ Clear")
        clr.setObjectName("danger")
        clr.clicked.connect(self.file_list.clear)
        btn_row.addWidget(clr)
        fl.addLayout(btn_row)
        lay.addWidget(file_grp)

        # Two-column options
        cols = QHBoxLayout()
        cols.setSpacing(14)

        left = QVBoxLayout()
        left.setSpacing(14)
        out_grp = QGroupBox("OUTPUT DIRECTORY")
        ol = QHBoxLayout(out_grp)
        ol.setSpacing(8)
        self.output_dir_edit = QLineEdit()
        self.output_dir_edit.setPlaceholderText("Choose output directory…")
        ob = QPushButton("Browse")
        ob.setFixedWidth(80)
        ob.clicked.connect(self._browse_output)
        ol.addWidget(self.output_dir_edit)
        ol.addWidget(ob)
        left.addWidget(out_grp)

        key_grp = QGroupBox("KEY FILE  (optional)")
        kl = QHBoxLayout(key_grp)
        kl.setSpacing(8)
        self.key_file_edit = QLineEdit()
        self.key_file_edit.setPlaceholderText("No key file selected")
        kb = QPushButton("Browse")
        kb.setFixedWidth(80)
        kb.clicked.connect(self._browse_key)
        kl.addWidget(self.key_file_edit)
        kl.addWidget(kb)
        left.addWidget(key_grp)
        cols.addLayout(left, 3)

        right = QVBoxLayout()
        right.setSpacing(14)
        pw_grp = QGroupBox("PASSWORD")
        pl = QVBoxLayout(pw_grp)
        pl.setSpacing(6)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.setPlaceholderText("Enter password…")
        self.password_edit.textChanged.connect(self._update_strength)
        pl.addWidget(self.password_edit)
        self.strength_bar = QProgressBar()
        self.strength_bar.setRange(0, 4)
        self.strength_bar.setValue(0)
        self.strength_bar.setFixedHeight(5)
        self.strength_bar.setTextVisible(False)
        pl.addWidget(self.strength_bar)
        self.strength_label = QLabel("Enter a password")
        self.strength_label.setStyleSheet(f"color:{C['text_xdim']};font-size:11px;")
        pl.addWidget(self.strength_label)
        right.addWidget(pw_grp)

        op_grp = QGroupBox("OPERATION")
        opl = QHBoxLayout(op_grp)
        opl.setSpacing(16)
        self.encrypt_radio = QRadioButton("🔒  Encrypt")
        self.decrypt_radio = QRadioButton("🔓  Decrypt")
        self.encrypt_radio.setChecked(True)
        opl.addWidget(self.encrypt_radio)
        opl.addWidget(self.decrypt_radio)
        opl.addStretch()
        right.addWidget(op_grp)
        cols.addLayout(right, 2)
        lay.addLayout(cols)

        self.shred_check = QCheckBox("🗑  Securely shred originals after encryption")
        lay.addWidget(self.shred_check)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setFixedHeight(8)
        self.progress_bar.setTextVisible(False)
        lay.addWidget(self.progress_bar)

        self.op_status_label = QLabel("Ready")
        self.op_status_label.setStyleSheet(f"color:{C['text_dim']};font-size:12px;")
        lay.addWidget(self.op_status_label)

        act = QHBoxLayout()
        act.setSpacing(10)
        self.start_btn = QPushButton("▶  Start")
        self.start_btn.setObjectName("primary")
        self.start_btn.setMinimumHeight(42)
        self.start_btn.setStyleSheet(f"""
            QPushButton#primary {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {C['accent']}, stop:1 {C['accent_dim']});
                color: #000; border: none; font-weight: 700;
                font-size: 14px; padding: 10px 28px; border-radius: 8px; letter-spacing: 0.5px;
            }}
            QPushButton#primary:hover {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #33ECFF, stop:1 {C['accent']}); color: #000;
            }}
            QPushButton#primary:disabled {{
                background: {C['surface2']}; color: {C['text_xdim']};
            }}
        """)
        self.start_btn.clicked.connect(self._start_operation)
        self.cancel_btn = QPushButton("✕  Cancel")
        self.cancel_btn.setObjectName("danger")
        self.cancel_btn.setMinimumHeight(42)
        self.cancel_btn.setEnabled(False)
        self.cancel_btn.clicked.connect(self._cancel_operation)
        act.addWidget(self.start_btn)
        act.addWidget(self.cancel_btn)
        lay.addLayout(act)
        lay.addStretch()
        return page

    def _build_logs_page(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(12)
        hdr = QLabel("Activity Log")
        hdr.setStyleSheet(f"font-size:17px;font-weight:700;color:{C['text']};")
        lay.addWidget(hdr)
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        lay.addWidget(self.logs_text)
        br = QHBoxLayout()
        rb = QPushButton("↻  Refresh")
        rb.clicked.connect(self._refresh_logs)
        cb = QPushButton("✕  Clear View")
        cb.setObjectName("danger")
        cb.clicked.connect(self.logs_text.clear)
        br.addWidget(rb)
        br.addWidget(cb)
        br.addStretch()
        lay.addLayout(br)
        return page

    def _build_license_page(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 20, 24, 20)
        lay.setSpacing(16)

        hdr = QLabel("License & Plan")
        hdr.setStyleSheet(f"font-size:17px;font-weight:700;color:{C['text']};")
        lay.addWidget(hdr)

        # Status card
        card = QWidget()
        card.setStyleSheet(
            f"background:{C['surface']};border-radius:10px;border:1px solid {C['border']};")
        cl = QVBoxLayout(card)
        cl.setContentsMargins(20, 14, 20, 14)
        self.lic_page_status = QLabel(self._license_info["message"])
        colour = C['green'] if self._license_info["valid"] else C['yellow']
        self.lic_page_status.setStyleSheet(
            f"color:{colour};font-size:14px;font-weight:600;")
        cl.addWidget(self.lic_page_status)
        lay.addWidget(card)

        # Tier comparison
        tiers_grp = QGroupBox("AVAILABLE TIERS")
        tl = QVBoxLayout(tiers_grp)
        current_tier = self._license_info.get("tier", "free")
        for t_key, t_caps in LICENSE_TIERS.items():
            active = (t_key == current_tier)
            row = QWidget()
            row.setStyleSheet(
                f"background:{'rgba(0,229,255,0.07)' if active else C['surface2']};"
                f"border-radius:6px;border:1px solid {C['accent'] if active else C['border']};")
            rl = QHBoxLayout(row)
            rl.setContentsMargins(14, 10, 14, 10)
            nl = QLabel(f"<b>{t_caps['label']}</b>")
            nl.setStyleSheet(f"color:{C['accent'] if active else C['text']};font-size:13px;")
            nl.setTextFormat(Qt.TextFormat.RichText)
            max_f = t_caps['max_files']
            dl = QLabel(
                f"Files: {'Unlimited' if max_f==-1 else max_f}  ·  "
                f"Shred: {'✓' if t_caps['shred'] else '✗'}  ·  "
                f"Batch: {'✓' if t_caps['batch'] else '✗'}")
            dl.setStyleSheet(f"color:{C['text_dim']};font-size:12px;")
            rl.addWidget(nl)
            rl.addWidget(dl)
            rl.addStretch()
            if active:
                badge = QLabel("  CURRENT  ")
                badge.setStyleSheet(
                    f"background:{C['accent']};color:#000;border-radius:8px;"
                    f"font-size:9px;font-weight:700;padding:2px 6px;")
                rl.addWidget(badge)
            tl.addWidget(row)
        lay.addWidget(tiers_grp)

        # Key entry
        key_grp = QGroupBox("ENTER / UPDATE LICENSE KEY")
        kl = QVBoxLayout(key_grp)
        kl.setSpacing(10)
        self.lic_key_edit = QLineEdit()
        self.lic_key_edit.setPlaceholderText("Paste your license key here…")
        kl.addWidget(self.lic_key_edit)
        kr = QHBoxLayout()
        ab = QPushButton("Apply License Key")
        ab.setObjectName("primaryApply")
        ab.setStyleSheet(f"""
            QPushButton#primaryApply {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 {C['accent']}, stop:1 {C['accent_dim']});
                color: #000; border: none; font-weight: 700;
                font-size: 14px; padding: 10px 28px; border-radius: 8px; letter-spacing: 0.5px;
            }}
            QPushButton#primaryApply:hover {{
                background: qlineargradient(x1:0,y1:0,x2:1,y2:0,
                    stop:0 #33ECFF, stop:1 {C['accent']}); color: #000;
            }}
            QPushButton#primaryApply:disabled {{
                background: {C['surface2']}; color: {C['text_xdim']};
            }}
        """)
        ab.clicked.connect(self._apply_license_page)
        rb2 = QPushButton("Remove License")
        rb2.setObjectName("danger")
        rb2.clicked.connect(self._remove_license)
        kr.addWidget(ab)
        kr.addWidget(rb2)
        kr.addStretch()
        kl.addLayout(kr)
        lay.addWidget(key_grp)

        mid = QLabel(
            f"Your Machine ID: <code style='color:{C['accent']}'>{_machine_id()}</code>"
            f"  (share with vendor for machine-locked licenses)")
        mid.setStyleSheet(f"color:{C['text_xdim']};font-size:11px;")
        mid.setTextFormat(Qt.TextFormat.RichText)
        lay.addWidget(mid)
        lay.addStretch()
        return page

    def _build_about_page(self) -> QWidget:
        page = QWidget()
        lay = QVBoxLayout(page)
        lay.setContentsMargins(24, 20, 24, 20)
        about = QTextEdit()
        about.setReadOnly(True)
        about.setHtml(f"""
        <style>
            body {{ color:{C['text']};font-family:'Segoe UI',sans-serif;font-size:13px;line-height:1.6; }}
            h2 {{ color:{C['accent']};margin-bottom:4px; }}
            h3 {{ color:{C['text']};margin-top:18px; }}
            code {{ color:{C['green']};background:{C['surface2']};padding:1px 4px;border-radius:3px; }}
            a {{ color:{C['accent']}; }}
            hr {{ border:1px solid {C['border']}; }}
            li {{ margin-bottom:4px; }}
            .muted {{ color:{C['text_dim']}; }}
            td,th {{ padding:3px 10px 3px 0;vertical-align:top; }}
        </style>
        <h2>⚿ CryptKey</h2>
        <p class='muted'><b>Version:</b> 2.1.0 &nbsp;|&nbsp;
           <b>Encryption:</b> AES-256-GCM &nbsp;|&nbsp;
           <b>KDF:</b> Argon2id &nbsp;|&nbsp;
           <b>Licensing:</b> Ed25519</p>
        <p>Professional-grade desktop encryption for files and directories.
           Designed for security, reliability, and ease of use.</p>
        <hr>
        <h3>Author</h3>
        <p><b>Leon Priest</b> &nbsp;—&nbsp;
           <a href='mailto:leonpriest76@gmail.com'>leonpriest76@gmail.com</a></p>
        <h3>Licensing</h3>
        <p>
            <b>Free:</b> MIT License — personal &amp; evaluation use (up to 10 files).<br>
            <b>Personal / Commercial:</b> Commercial license required.
            Contact the author for pricing and volume discounts.
        </p>
        <hr>
        <h3>Cryptographic Design</h3>
        <ul>
            <li><b>AES-256-GCM</b> — authenticated encryption (confidentiality + integrity)</li>
            <li><b>Argon2id</b> — memory-hard KDF (time=4, memory=128 MB, parallelism=8)</li>
            <li><b>zlib</b> — compression applied before encryption</li>
            <li><b>SHA-256</b> — plaintext integrity verification on decryption</li>
            <li><b>Secure shred</b> — 3-pass random overwrite (Personal/Commercial)</li>
        </ul>
        <h3>File Format (.enc)</h3>
        <table>
          <tr style='color:{C['text_dim']};font-size:11px;'>
            <th>Field</th><th>Size</th><th>Purpose</th></tr>
          <tr><td><code>MAGIC</code></td><td>4 B</td><td>Format identifier <code>ENC1</code></td></tr>
          <tr><td><code>SALT</code></td><td>16 B</td><td>Argon2 salt (random per file)</td></tr>
          <tr><td><code>NONCE</code></td><td>12 B</td><td>AES-GCM IV (random per file)</td></tr>
          <tr><td><code>HEADER_LEN</code></td><td>4 B</td><td>Encrypted header byte count</td></tr>
          <tr><td><code>HEADER</code></td><td>variable</td><td>Encrypted JSON (filename + SHA-256)</td></tr>
          <tr><td><code>CIPHERTEXT</code></td><td>variable</td><td>zlib-compressed + AES-GCM ciphertext</td></tr>
          <tr><td><code>TAG</code></td><td>16 B</td><td>AES-GCM authentication tag</td></tr>
        </table>
        <h3>Log locations</h3>
        <p>
            <b>Windows:</b> <code>%APPDATA%\\CryptKey\\cryptkey.log</code><br>
            <b>Linux/macOS:</b> <code>~/.local/share/CryptKey/cryptkey.log</code>
        </p>
        """)
        lay.addWidget(about)
        return page

    # ── Navigation ────────────────────────────────────────

    def _switch_page(self, key: str):
        for k, btn in self._nav_btns.items():
            btn.setChecked(k == key)
        self.stack.setCurrentIndex(self._page_index[key])
        if key == "logs":
            self._refresh_logs()

    # ── Operations ────────────────────────────────────────

    def _add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        for f in files:
            self.file_list.addItem(f)

    def _add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            self.file_list.addItem(folder)

    def _browse_output(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if folder:
            self.output_dir_edit.setText(folder)

    def _browse_key(self):
        file, _ = QFileDialog.getOpenFileName(self, "Select Key File")
        if file:
            self.key_file_edit.setText(file)

    def _update_strength(self):
        pw = self.password_edit.text()
        result = self.crypto.validate_password(pw)
        score = result['score']
        labels  = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
        colours = [C['red'], C['red'], C['yellow'], C['green'], C['green']]
        if score < 0:
            self.strength_label.setText("Enter a password")
            self.strength_label.setStyleSheet(f"color:{C['text_xdim']};font-size:11px;")
            self.strength_bar.setValue(0)
            return
        self.strength_bar.setValue(score + 1)
        colour = colours[score]
        self.strength_bar.setStyleSheet(
            f"QProgressBar::chunk {{ background:{colour}; border-radius:5px; }}")
        text = labels[score]
        if result['feedback'].get('warning'):
            text += f" – {result['feedback']['warning']}"
        self.strength_label.setText(text)
        self.strength_label.setStyleSheet(f"color:{colour};font-size:11px;")

    def _ctx_menu(self, pos):
        menu = QMenu()
        ra = menu.addAction("✕  Remove Selected")
        action = menu.exec(self.file_list.mapToGlobal(pos))
        if action == ra:
            for item in self.file_list.selectedItems():
                self.file_list.takeItem(self.file_list.row(item))

    def _start_operation(self):
        if not self.file_list.count():
            QMessageBox.warning(self, "No Files", "Add at least one file or folder.")
            return
        if not self.output_dir_edit.text():
            QMessageBox.warning(self, "No Output", "Please specify an output directory.")
            return
        if not os.path.isdir(self.output_dir_edit.text()):
            QMessageBox.warning(self, "Invalid Directory", "Output directory does not exist.")
            return
        if not self.password_edit.text():
            QMessageBox.warning(self, "No Password", "Please enter a password.")
            return
        pw_result = self.crypto.validate_password(self.password_edit.text())
        if pw_result['score'] < 3:
            QMessageBox.warning(self, "Weak Password",
                "Password must score Strong or better (3+/4).\nPlease choose a stronger password.")
            return

        # Collect files
        input_paths = []
        for i in range(self.file_list.count()):
            path = self.file_list.item(i).text()
            if os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for file in files:
                        input_paths.append(os.path.join(root, file))
            else:
                input_paths.append(path)

        # License: file limit
        max_f = self._license_caps['max_files']
        if max_f != -1 and len(input_paths) > max_f:
            QMessageBox.warning(self, "License Limit",
                f"Your {self._license_caps['label']} license allows up to {max_f} files per operation.\n"
                f"You selected {len(input_paths)} files.\n\nUpgrade to process more files.")
            return

        # License: shred
        if self.shred_check.isChecked() and not self._license_caps['shred']:
            QMessageBox.warning(self, "Feature Locked",
                "Secure shredding requires a Personal or Commercial license.\n"
                "Please upgrade or uncheck 'Shred originals'.")
            return

        operation = 'encrypt' if self.encrypt_radio.isChecked() else 'decrypt'
        self.cancel_flag = [False]
        self.thread = WorkerThread(
            self.crypto, operation, input_paths,
            self.output_dir_edit.text(), self.password_edit.text(),
            self.key_file_edit.text() or None,
            self.shred_check.isChecked())
        self.thread.cancel_flag = self.cancel_flag
        self.thread.progress.connect(self.progress_bar.setValue)
        self.thread.status.connect(self._on_status)
        self.thread.finished.connect(self._op_finished)
        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.progress_bar.setValue(0)
        self.thread.start()

    def _on_status(self, msg: str):
        self.op_status_label.setText(msg)
        self.status_bar.setText(f"  {msg}")

    def _cancel_operation(self):
        self.cancel_flag[0] = True
        self._on_status("Cancelling…")
        self.cancel_btn.setEnabled(False)

    def _op_finished(self, success: int, total: int):
        self.cancel_flag[0] = False
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setValue(100)
        msg = f"Done – {success}/{total} files processed successfully."
        self._on_status(msg)
        if success < total:
            QMessageBox.warning(self, "Partial Completion",
                f"{total - success} file(s) failed. Check the Activity Log for details.")
        else:
            QTimer.singleShot(1500, lambda: self.progress_bar.setValue(0))
        self._refresh_logs()

    # ── Logs ──────────────────────────────────────────────

    def _refresh_logs(self):
        try:
            log_path = LOG_FILE_PATH or (
                Path(os.getenv('APPDATA', Path.home())) / "CryptKey" / "cryptkey.log")
            if os.path.exists(str(log_path)):
                with open(log_path, 'r', encoding='utf-8', errors='replace') as f:
                    self.logs_text.setPlainText(f.read())
                self.logs_text.moveCursor(self.logs_text.textCursor().MoveOperation.End)
            else:
                self.logs_text.setPlainText("No log file found yet.")
        except Exception as e:
            self.logs_text.setPlainText(f"Error loading log: {e}")

    # ── License ───────────────────────────────────────────

    def _apply_license_ui(self):
        caps = self._license_caps
        self.header.refresh(self._license_info)
        if not caps['shred']:
            self.shred_check.setEnabled(False)
            self.shred_check.setToolTip(
                "Upgrade to Personal or Commercial to enable secure shredding.")
        else:
            self.shred_check.setEnabled(True)
            self.shred_check.setToolTip("")

    def _apply_license_page(self):
        key_str = self.lic_key_edit.text().strip()
        if not key_str:
            QMessageBox.warning(self, "No Key", "Please paste a license key.")
            return
        info = validate_license_key(key_str)
        if info["valid"]:
            LicenseStore.save(key_str)
        self._on_license_updated(info)
        colour = C['green'] if info["valid"] else C['red']
        self.lic_page_status.setText(info["message"])
        self.lic_page_status.setStyleSheet(
            f"color:{colour};font-size:14px;font-weight:600;")
        # Reload page to refresh tier cards
        idx = self._page_index["license"]
        old = self.stack.widget(idx)
        new = self._build_license_page()
        self.stack.insertWidget(idx, new)
        self.stack.removeWidget(old)
        old.deleteLater()
        self.stack.setCurrentIndex(idx)

    def _remove_license(self):
        LicenseStore.clear()
        info = validate_license_key("")
        self._on_license_updated(info)
        self.lic_page_status.setText(info["message"])
        self.lic_page_status.setStyleSheet(
            f"color:{C['yellow']};font-size:14px;font-weight:600;")

    def _on_license_updated(self, info: dict):
        self._license_info = info
        self._license_caps = LICENSE_TIERS.get(
            info.get("tier", "free"), LICENSE_TIERS["free"])
        self._apply_license_ui()
        logging.info(f"License updated: {info['message']}")

    # ── Settings ──────────────────────────────────────────

    def _load_settings(self):
        s = QSettings("CryptKey", "Settings")
        self.output_dir_edit.setText(s.value("output_dir", ""))
        self.key_file_edit.setText(s.value("key_file", ""))

    def closeEvent(self, event):
        s = QSettings("CryptKey", "Settings")
        s.setValue("output_dir", self.output_dir_edit.text())
        s.setValue("key_file", self.key_file_edit.text())
        event.accept()

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if os.path.exists(path):
                self.file_list.addItem(path)


# ─────────────────────────────────────────────────────────
#  CLI
# ─────────────────────────────────────────────────────────
def run_cli(args):
    lic = validate_license_key(LicenseStore.load())
    caps = LICENSE_TIERS.get(lic.get("tier", "free"), LICENSE_TIERS["free"])
    if not lic["valid"] and lic.get("tier") not in (None, "free"):
        print(f"License warning: {lic['message']}")

    crypto = CryptoEngine()
    files_to_process = []
    for path in args.input_paths:
        if not os.path.exists(path):
            print(f"ERROR: Path does not exist: {path}")
            continue
        if os.path.isdir(path):
            for root, _, files in os.walk(path):
                for file in files:
                    files_to_process.append(os.path.join(root, file))
        else:
            files_to_process.append(path)

    max_f = caps['max_files']
    if max_f != -1 and len(files_to_process) > max_f:
        print(f"ERROR: {caps['label']} license allows up to {max_f} files per operation.")
        sys.exit(1)

    password = args.password or getpass.getpass("Enter password: ")
    success_count = 0
    for input_file in files_to_process:
        rel_path = os.path.basename(input_file)
        output_path = os.path.join(args.output_dir,
                                   rel_path + ('.enc' if not args.decrypt else ''))
        if args.decrypt:
            ok = crypto.decrypt_file(input_file, args.output_dir, password,
                                     key_file=args.key_file, cli_mode=True)
        else:
            ok = crypto.encrypt_file(input_file, output_path, password,
                                     key_file=args.key_file, cli_mode=True)
            if ok and args.shred:
                if not caps['shred']:
                    print("WARNING: Shredding requires Personal/Commercial license – skipped.")
                else:
                    crypto.shred_file(input_file)
        if ok:
            success_count += 1

    print(f"\nDone. {success_count}/{len(files_to_process)} files processed successfully.")


# ─────────────────────────────────────────────────────────
#  ENTRY POINT
# ─────────────────────────────────────────────────────────
def main():
    setup_logging()
    try:
        parser = argparse.ArgumentParser(
            description="CryptKey 2.1 – Secure File & Directory Encryptor")
        parser.add_argument('input_paths', nargs='*')
        parser.add_argument('--cli', action='store_true')
        parser.add_argument('-d', '--decrypt', action='store_true')
        parser.add_argument('-o', '--output-dir')
        parser.add_argument('-p', '--password')
        parser.add_argument('-k', '--key-file')
        parser.add_argument('--shred', action='store_true')
        args = parser.parse_args()

        if args.cli or args.input_paths:
            if not args.input_paths:
                parser.error("At least one input path is required.")
            if not args.output_dir:
                parser.error("--output-dir is required.")
            if not os.path.isdir(args.output_dir):
                parser.error(f"Output directory does not exist: {args.output_dir}")
            if args.key_file and not os.path.exists(args.key_file):
                parser.error(f"Key file not found: {args.key_file}")
            run_cli(args)
        else:
            app = QApplication(sys.argv)
            app.setStyleSheet(STYLESHEET)
            app.setStyle("Fusion")
            app.setWindowIcon(QIcon(resource_path("icon.ico")))
            window = FileEncryptor()
            window.show()
            sys.exit(app.exec())

    except Exception as e:
        logging.error(f"Critical: {e}\n{traceback.format_exc()}")
        try:
            app = QApplication.instance() or QApplication(sys.argv)
            app.setStyleSheet(STYLESHEET)
            box = QMessageBox()
            box.setIcon(QMessageBox.Icon.Critical)
            box.setWindowTitle("CryptKey – Fatal Error")
            box.setText("A critical error occurred.")
            box.setInformativeText(f"Log: {LOG_FILE_PATH or 'console'}\n\n{e}")
            box.exec()
        except Exception:
            print(f"Fatal: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

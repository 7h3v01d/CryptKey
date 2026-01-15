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
import base64
import time
from pathlib import Path
from typing import List, Optional, Dict, Any, Callable
from PyQt6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QTabWidget,
    QPushButton, QFileDialog, QLineEdit, QLabel, QProgressBar,
    QMessageBox, QRadioButton, QGroupBox, QCheckBox,
    QListWidget, QMenu, QTextEdit, QScrollArea
)
from PyQt6.QtCore import Qt, QThread, pyqtSignal, QSettings
from PyQt6.QtGui import QDragEnterEvent, QDropEvent, QIcon, QPixmap, QImage, QFont
from argon2 import PasswordHasher, low_level
from argon2.exceptions import HashingError
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.backends import default_backend
from zxcvbn import zxcvbn
from tqdm import tqdm

# --- Self-Contained Icon ---
ICON_SVG_B64 = b'PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHZpZXdCb3g9IjAgMCAyNCAyNCIgZmlsbD0iIzQ0NDQ0NCI+PHBhdGggZD0iTTE4IDhoLTFWNmMwLTIuNzYtMi4yNC01LTUtNVM3IDMuMjQgNyA2djJINmMtMS4xIDAtMiAuOS0yIDJ2MTBjMCAxLjEuOSAyIDIgMmgxMmMxLjEgMCAyLS45IDItMlYxMGMwLTEuMS0uOS0yLTItMnpmTTkgNmMwLTEuNjYgMS4zNC0zIDMtM3MzIDEuMzQgMyAzdjJIOVY2eiIvPjwvc3ZnPg=='

# --- Global variable for log file path ---
LOG_FILE_PATH = None

# --- File format constants ---
MAGIC_NUMBER = b'ENC1'  # New format identifier
MAGIC_SIZE = 4
CHUNK_SIZE = 8192
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16
HEADER_LEN_SIZE = 4
KEY_LEN = 32
INVALID_MAGIC_NUMBERS = {b'INVA'}  # Known invalid magic numbers

def setup_logging():
    """Configure logging to a user-writable directory."""
    global LOG_FILE_PATH
    if logging.getLogger().hasHandlers():
        return
    try:
        if sys.platform == "win32":
            log_dir = Path(os.getenv('APPDATA', Path.home())) / "FileEncryptor"
        else:
            log_dir = Path.home() / ".local/share/FileEncryptor"

        log_dir.mkdir(parents=True, exist_ok=True)
        log_file = log_dir / 'file_encryptor.log'
        
        logging.basicConfig(
            filename=log_file, level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s', force=True)
        LOG_FILE_PATH = str(log_file)
        logging.info("--- Logging initialized successfully ---")
        return log_file
    except Exception as e:
        logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s', force=True)
        logging.error(f"Failed to configure file logging. Reason: {e}")
        logging.info("Logging will proceed in the console.")
        return None

class CryptoEngine:
    """Handles all cryptographic operations. Does not interact with PyQt."""
    def __init__(self):
        self.backend = default_backend()
        self.ph = PasswordHasher(time_cost=4, memory_cost=2**17, parallelism=8)

    def derive_key(self, password: str, salt: bytes, key_file: Optional[str] = None) -> bytes:
        try:
            secret = password.encode('utf-8')
            if key_file and os.path.exists(key_file):
                with open(key_file, 'rb') as f:
                    key_data = f.read(1024)
                    if len(key_data) > 1024:
                        raise ValueError("Key file too large (max 1KB)")
                    digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
                    digest.update(key_data)
                    secret += digest.finalize()
            return low_level.hash_secret_raw(
                secret=secret, salt=salt, time_cost=self.ph.time_cost,
                memory_cost=self.ph.memory_cost, parallelism=self.ph.parallelism,
                hash_len=KEY_LEN, type=low_level.Type.ID)
        except HashingError as e:
            logging.error(f"Key derivation failed: {e}")
            raise ValueError("Key derivation failed.")

    @staticmethod
    def validate_password(password: str) -> Dict[str, Any]:
        if not password: return {'score': -1, 'feedback': {'warning': 'Password cannot be empty.'}}
        return zxcvbn(password)

    def _cleanup_partial_file(self, path: str):
        if path and os.path.exists(path):
            try:
                os.remove(path)
                logging.warning(f"Cleaned up partial file: {path}")
            except OSError as e:
                logging.error(f"Failed to clean up partial file {path}: {e}")

    def shred_file(self, file_path: str, passes: int = 3) -> bool:
        """Securely shred a file by overwriting it multiple times."""
        try:
            file_size = os.path.getsize(file_path)
            with open(file_path, 'r+b') as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
            os.remove(file_path)
            logging.info(f"Successfully shredded file: {file_path}")
            return True
        except Exception as e:
            logging.error(f"Failed to shred file {file_path}: {e}")
            return False

    def encrypt_file(self, input_path: str, output_path: str, password: str,
                     key_file: Optional[str] = None,
                     progress_callback: Optional[Callable[[int], None]] = None,
                     status_signal: Optional[pyqtSignal] = None,
                     cancel_flag: Optional[List[bool]] = None,
                     cli_mode: bool = False) -> bool:
        try:
            os.makedirs(os.path.dirname(output_path), exist_ok=True)
            salt, nonce = secrets.token_bytes(SALT_SIZE), secrets.token_bytes(NONCE_SIZE)
            key = self.derive_key(password, salt, key_file)
            digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
            with open(input_path, 'rb') as f_in:
                while chunk := f_in.read(CHUNK_SIZE):
                    digest.update(chunk)
            metadata = {
                'original_filename': os.path.basename(input_path),
                'sha256': digest.finalize().hex()
            }
            header_bytes = json.dumps(metadata).encode('utf-8')
            header_len_bytes = len(header_bytes).to_bytes(HEADER_LEN_SIZE, 'big')
            encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.backend).encryptor()
            total_size = os.path.getsize(input_path)
            processed_bytes = 0
            last_progress = -1
            pbar = tqdm(total=total_size, unit="B", unit_scale=True, desc=f"Encrypting {os.path.basename(input_path)}", leave=False) if cli_mode else None

            with open(input_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
                f_out.write(MAGIC_NUMBER)
                f_out.write(salt)
                f_out.write(nonce)
                f_out.write(header_len_bytes)
                f_out.write(encryptor.update(header_bytes))
                compressor = zlib.compressobj()
                while True:
                    if cancel_flag and cancel_flag[0]: raise InterruptedError("Operation cancelled.")
                    chunk = f_in.read(CHUNK_SIZE)
                    if not chunk: break
                    compressed_chunk = compressor.compress(chunk)
                    if compressed_chunk: f_out.write(encryptor.update(compressed_chunk))
                    processed_bytes += len(chunk)
                    if pbar: pbar.update(len(chunk))
                    if progress_callback and total_size >= 1048576:
                        progress = int((processed_bytes / total_size) * 100)
                        if progress > last_progress:
                            progress_callback(progress)
                            last_progress = progress
                remaining_compressed = compressor.flush()
                if remaining_compressed: f_out.write(encryptor.update(remaining_compressed))
                f_out.write(encryptor.finalize())
                f_out.write(encryptor.tag)
                f_out.flush()
                os.fsync(f_out.fileno())

            if pbar: pbar.close()
            logging.info(f"Successfully encrypted {input_path} to {output_path}")
            if status_signal: status_signal.emit(f"Encrypted: {os.path.basename(input_path)}")
            return True
        except Exception as e:
            self._cleanup_partial_file(output_path)
            error_msg = f"Encryption failed for {os.path.basename(input_path)}: {e}"
            logging.error(error_msg + f"\n{traceback.format_exc()}")
            if status_signal: status_signal.emit(error_msg)
            if cli_mode: print(f"ERROR: {error_msg}")
            return False

    def decrypt_file(self, input_path: str, output_dir: str, password: str,
                     key_file: Optional[str] = None,
                     progress_callback: Optional[Callable[[int], None]] = None,
                     status_signal: Optional[pyqtSignal] = None,
                     cancel_flag: Optional[List[bool]] = None,
                     cli_mode: bool = False) -> bool:
        output_path = None
        max_retries = 3
        retry_delay = 0.1  # seconds
        for attempt in range(max_retries):
            try:
                file_size = os.path.getsize(input_path)
                logging.info(f"Attempt {attempt + 1}/{max_retries} to decrypt {input_path}, file size: {file_size} bytes")
                if file_size < MAGIC_SIZE:
                    raise ValueError("File is too short to be a valid encrypted file.")
                with open(input_path, 'rb') as f_in:
                    # Check magic number first
                    magic = f_in.read(MAGIC_SIZE)
                    logging.info(f"File {input_path} has magic number: {magic!r}")
                    if magic in INVALID_MAGIC_NUMBERS:
                        raise ValueError(f"Invalid file format: magic number {magic!r} is not supported.")
                    if magic != MAGIC_NUMBER:
                        logging.info(f"Attempting legacy format decryption for {input_path}")
                        expected_legacy_size = SALT_SIZE + NONCE_SIZE + TAG_SIZE + 1
                        if file_size < expected_legacy_size:
                            raise ValueError(f"Invalid file format: file is too short for legacy decryption (got {file_size} bytes, expected at least {expected_legacy_size}).")
                        f_in.seek(0)
                        salt = f_in.read(SALT_SIZE)
                        if len(salt) != SALT_SIZE:
                            raise ValueError(f"Invalid legacy file format: incomplete salt (got {len(salt)} bytes).")
                        nonce = f_in.read(NONCE_SIZE)
                        if len(nonce) != NONCE_SIZE:
                            raise ValueError(f"Invalid legacy file format: incomplete nonce (got {len(nonce)} bytes).")
                        remaining_size = file_size - SALT_SIZE - NONCE_SIZE - TAG_SIZE
                        if remaining_size <= 0:
                            raise ValueError("Invalid legacy file format: no ciphertext available.")
                        key = self.derive_key(password, salt, key_file)
                        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.backend).decryptor()
                        output_path = os.path.join(output_dir, f"decrypted_{os.path.basename(input_path).replace('.enc', '')}")
                        with open(output_path, 'wb') as f_out:
                            ciphertext = f_in.read(remaining_size)
                            tag = f_in.read(TAG_SIZE)
                            if len(tag) != TAG_SIZE:
                                raise ValueError(f"Invalid legacy file format: tag is {len(tag)} bytes, expected {TAG_SIZE}.")
                            try:
                                decrypted_data = decryptor.update(ciphertext) + decryptor.finalize_with_tag(tag)
                            except InvalidTag as e:
                                raise ValueError(f"Legacy decryption failed: invalid tag, possibly wrong password or corrupted file.") from e
                            try:
                                decompressed_data = zlib.decompress(decrypted_data)
                            except zlib.error as ze:
                                logging.error(f"Legacy decompression failed for {input_path}: {ze}")
                                raise ValueError(f"Legacy decompression failed: {ze}")
                            f_out.write(decompressed_data)
                            f_out.flush()
                            os.fsync(f_out.fileno())
                        logging.info(f"Successfully decrypted legacy {input_path} to {output_path}")
                        if status_signal: status_signal.emit(f"Decrypted (legacy): {os.path.basename(output_path)}")
                        return True

                    # New format decryption
                    expected_min_size = MAGIC_SIZE + SALT_SIZE + NONCE_SIZE + HEADER_LEN_SIZE + TAG_SIZE + 1
                    if file_size < expected_min_size:
                        raise ValueError(f"Invalid new format file: file is too short (got {file_size} bytes, expected at least {expected_min_size}).")
                    
                    salt = f_in.read(SALT_SIZE)
                    nonce = f_in.read(NONCE_SIZE)
                    header_len_bytes = f_in.read(HEADER_LEN_SIZE)
                    if len(salt) != SALT_SIZE or len(nonce) != NONCE_SIZE or len(header_len_bytes) != HEADER_LEN_SIZE:
                        raise ValueError(f"Invalid new format file: incomplete header components (salt: {len(salt)}, nonce: {len(nonce)}, header_len: {len(header_len_bytes)}).")
                    
                    header_len = int.from_bytes(header_len_bytes, 'big')
                    logging.info(f"Header length: {header_len} bytes")
                    if file_size < MAGIC_SIZE + SALT_SIZE + NONCE_SIZE + HEADER_LEN_SIZE + header_len + TAG_SIZE:
                        raise ValueError(f"Invalid new format file: insufficient size for header and tag (got {file_size} bytes, expected at least {MAGIC_SIZE + SALT_SIZE + NONCE_SIZE + HEADER_LEN_SIZE + header_len + TAG_SIZE}).")
                    
                    key = self.derive_key(password, salt, key_file)
                    decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=self.backend).decryptor()
                    encrypted_header = f_in.read(header_len)
                    total_size = file_size - (MAGIC_SIZE + SALT_SIZE + NONCE_SIZE + HEADER_LEN_SIZE + header_len + TAG_SIZE)
                    logging.info(f"Ciphertext size: {total_size} bytes")
                    processed_bytes = 0
                    last_progress = -1
                    pbar = tqdm(total=total_size, unit="B", unit_scale=True, desc=f"Decrypting {os.path.basename(input_path)}", leave=False) if cli_mode else None
                    output_path = None

                    # Read the entire ciphertext and tag
                    ciphertext = f_in.read(total_size)
                    tag = f_in.read(TAG_SIZE)
                    if len(tag) != TAG_SIZE:
                        raise ValueError(f"Invalid new format file: tag is {len(tag)} bytes, expected {TAG_SIZE}.")

                    # Decrypt header and ciphertext together
                    try:
                        decrypted_data = decryptor.update(encrypted_header + ciphertext) + decryptor.finalize_with_tag(tag)
                    except InvalidTag as e:
                        logging.error(f"Decryption attempt {attempt + 1} failed with InvalidTag: {e}")
                        if attempt < max_retries - 1:
                            logging.info(f"Retrying decryption after {retry_delay} seconds...")
                            time.sleep(retry_delay)
                            continue
                        raise ValueError(f"Decryption failed after {max_retries} attempts: invalid tag, possibly wrong password or corrupted file.") from e

                    # Extract header and ciphertext
                    header_json = decrypted_data[:header_len]
                    decrypted_ciphertext = decrypted_data[header_len:]
                    
                    try:
                        metadata = json.loads(header_json.decode('utf-8'))
                    except (UnicodeDecodeError, json.JSONDecodeError) as e:
                        raise ValueError(f"Decryption failed: Incorrect password or corrupted file. Original error: {str(e)}")
                    
                    original_filename = metadata.get('original_filename', os.path.basename(input_path).replace('.enc', ''))
                    output_path = os.path.join(output_dir, original_filename)
                    os.makedirs(os.path.dirname(output_path), exist_ok=True)

                    with open(output_path, 'wb') as f_out:
                        decompressor = zlib.decompressobj()
                        decompressed_chunk = decompressor.decompress(decrypted_ciphertext)
                        if decompressed_chunk:
                            f_out.write(decompressed_chunk)
                        remaining_decompressed = decompressor.flush()
                        if remaining_decompressed:
                            f_out.write(remaining_decompressed)
                        f_out.flush()
                        os.fsync(f_out.fileno())

                    if pbar:
                        pbar.update(total_size)
                        pbar.close()

                    digest = hashes.Hash(hashes.SHA256(), backend=self.backend)
                    with open(output_path, 'rb') as f_out:
                        while chunk := f_out.read(CHUNK_SIZE):
                            digest.update(chunk)
                    calculated_sha256 = digest.finalize().hex()
                    if calculated_sha256 != metadata.get('sha256'):
                        logging.warning(f"SHA256 mismatch for {output_path}: expected {metadata.get('sha256')}, got {calculated_sha256}")
                        self._cleanup_partial_file(output_path)
                        raise ValueError("Decryption failed: SHA256 checksum does not match.")
                    
                    logging.info(f"Successfully decrypted {input_path} to {output_path}")
                    if status_signal: status_signal.emit(f"Decrypted: {os.path.basename(output_path)}")
                    return True
            except Exception as e:
                if output_path:
                    self._cleanup_partial_file(output_path)
                error_msg = f"Decryption failed for {os.path.basename(input_path)}: {e}"
                logging.error(error_msg + f"\n{traceback.format_exc()}")
                if status_signal: status_signal.emit(error_msg)
                if cli_mode: print(f"ERROR: {error_msg}")
                return False

class WorkerThread(QThread):
    progress = pyqtSignal(int)
    status = pyqtSignal(str)
    finished = pyqtSignal()

    def __init__(self, crypto: CryptoEngine, operation: str, input_paths: List[str], output_dir: str,
                 password: str, key_file: Optional[str], shred: bool):
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
        for input_path in self.input_paths:
            if self.cancel_flag[0]: break
            base_path = os.path.dirname(input_path)
            rel_path = os.path.relpath(input_path, base_path) if os.path.isdir(input_path) else os.path.basename(input_path)
            output_path = os.path.join(self.output_dir, rel_path + ('.enc' if self.operation == 'encrypt' else ''))
            if self.operation == 'encrypt':
                success = self.crypto.encrypt_file(
                    input_path, output_path, self.password, self.key_file,
                    progress_callback=self.progress.emit, status_signal=self.status, cancel_flag=self.cancel_flag)
                if success and self.shred:
                    self.crypto.shred_file(input_path)
            else:
                success = self.crypto.decrypt_file(
                    input_path, self.output_dir, self.password, self.key_file,
                    progress_callback=self.progress.emit, status_signal=self.status, cancel_flag=self.cancel_flag)
        self.finished.emit()

class FileEncryptor(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("CryptKey 1.6.0 - Secure File Encryptor")
        self.setGeometry(100, 100, 800, 600)
        self.crypto = CryptoEngine()
        self.cancel_flag = [False]
        self.init_ui()
        self.load_settings()
        svg_data = base64.b64decode(ICON_SVG_B64)
        image = QImage.fromData(svg_data)
        self.setWindowIcon(QIcon(QPixmap.fromImage(image)))

    def init_ui(self):
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        main_layout = QVBoxLayout(central_widget)

        # Create tab widget
        self.tabs = QTabWidget()
        main_layout.addWidget(self.tabs)

        # Main tab
        main_tab = QWidget()
        main_layout_tab = QVBoxLayout(main_tab)

        # File selection
        file_group = QGroupBox("Files")
        file_layout = QVBoxLayout(file_group)
        self.file_list = QListWidget()
        self.file_list.setAcceptDrops(True)
        self.file_list.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.file_list.customContextMenuRequested.connect(self.show_context_menu)
        self.file_list.setMinimumHeight(100)
        file_layout.addWidget(self.file_list)
        file_buttons = QHBoxLayout()
        self.add_files_btn = QPushButton("Add Files")
        self.add_files_btn.clicked.connect(self.add_files)
        self.add_folder_btn = QPushButton("Add Folder")
        self.add_folder_btn.clicked.connect(self.add_folder)
        self.clear_btn = QPushButton("Clear")
        self.clear_btn.clicked.connect(self.file_list.clear)
        file_buttons.addWidget(self.add_files_btn)
        file_buttons.addWidget(self.add_folder_btn)
        file_buttons.addWidget(self.clear_btn)
        file_layout.addLayout(file_buttons)
        main_layout_tab.addWidget(file_group)

        # Output directory
        output_group = QGroupBox("Output Directory")
        output_layout = QHBoxLayout(output_group)
        self.output_dir_edit = QLineEdit()
        self.output_dir_btn = QPushButton("Browse")
        self.output_dir_btn.clicked.connect(self.browse_output_dir)
        output_layout.addWidget(QLabel("Output:"))
        output_layout.addWidget(self.output_dir_edit)
        output_layout.addWidget(self.output_dir_btn)
        main_layout_tab.addWidget(output_group)

        # Password
        password_group = QGroupBox("Password")
        password_layout = QVBoxLayout(password_group)
        self.password_edit = QLineEdit()
        self.password_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.password_edit.textChanged.connect(self.update_password_strength)
        password_layout.addWidget(QLabel("Password:"))
        password_layout.addWidget(self.password_edit)
        self.strength_label = QLabel("Password Strength: N/A")
        password_layout.addWidget(self.strength_label)
        main_layout_tab.addWidget(password_group)

        # Key file
        key_group = QGroupBox("Key File (Optional)")
        key_layout = QHBoxLayout(key_group)
        self.key_file_edit = QLineEdit()
        self.key_file_btn = QPushButton("Browse")
        self.key_file_btn.clicked.connect(self.browse_key_file)
        key_layout.addWidget(QLabel("Key File:"))
        key_layout.addWidget(self.key_file_edit)
        key_layout.addWidget(self.key_file_btn)
        main_layout_tab.addWidget(key_group)

        # Operation selection
        operation_group = QGroupBox("Operation")
        operation_layout = QHBoxLayout(operation_group)
        self.encrypt_radio = QRadioButton("Encrypt")
        self.decrypt_radio = QRadioButton("Decrypt")
        self.encrypt_radio.setChecked(True)
        operation_layout.addWidget(self.encrypt_radio)
        operation_layout.addWidget(self.decrypt_radio)
        main_layout_tab.addWidget(operation_group)

        # Shred option
        self.shred_check = QCheckBox("Shred original files after encryption")
        main_layout_tab.addWidget(self.shred_check)

        # Progress and status
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        main_layout_tab.addWidget(self.progress_bar)
        self.status_label = QLabel("Ready")
        main_layout_tab.addWidget(self.status_label)

        # Action buttons
        action_layout = QHBoxLayout()
        self.start_btn = QPushButton("Start")
        self.start_btn.clicked.connect(self.start_operation)
        self.cancel_btn = QPushButton("Cancel")
        self.cancel_btn.clicked.connect(self.cancel_operation)
        self.cancel_btn.setEnabled(False)
        action_layout.addWidget(self.start_btn)
        action_layout.addWidget(self.cancel_btn)
        main_layout_tab.addLayout(action_layout)
        main_layout_tab.addStretch()

        # Help tab
        help_tab = QWidget()
        help_layout = QVBoxLayout(help_tab)
        help_tabs = QTabWidget()
        
        # View Logs subtab
        logs_widget = QWidget()
        logs_layout = QVBoxLayout(logs_widget)
        logs_label = QLabel("Log File Contents:")
        logs_layout.addWidget(logs_label)
        self.logs_text = QTextEdit()
        self.logs_text.setReadOnly(True)
        self.logs_text.setFont(QFont("Courier New", 10))
        logs_scroll = QScrollArea()
        logs_scroll.setWidget(self.logs_text)
        logs_scroll.setWidgetResizable(True)
        logs_layout.addWidget(logs_scroll)
        refresh_logs_btn = QPushButton("Refresh Logs")
        refresh_logs_btn.clicked.connect(self.refresh_logs)
        logs_layout.addWidget(refresh_logs_btn)
        help_tabs.addTab(logs_widget, "View Logs")
        
        # About subtab
        about_widget = QWidget()
        about_layout = QVBoxLayout(about_widget)
        about_text = QTextEdit()
        about_text.setReadOnly(True)
        about_text.setText("""
        <h2>CryptKey</h2>
        <p><b>Version:</b> 1.6.0</p>
        <p><b>Description:</b> A secure yet user-friendly application for encrypting and decrypting files and folders. CryptKey uses AES-256-GCM encryption with Argon2 password derivation, supports legacy file formats, and includes secure shredding of originals.</p>

        <p><b>Author:</b> Leon Priest</p>
        <p><b>Contact:</b> leonpriest76@gmail.com</p>
        <p><b>License:</b> MIT License</p>

        <hr>

        <h3>Key Features</h3>
        <ul>
        <li><b>File & Folder Protection:</b> Encrypt entire directories while preserving structure.</li>
        <li><b>Decryption:</b> Open modern or legacy <code>.enc</code> files seamlessly.</li>
        <li><b>Key File Support:</b> Optional key files for enhanced security.</li>
        <li><b>Integrity Verification:</b> SHA-256 hash check to ensure files are uncorrupted.</li>
        <li><b>Secure Shredding:</b> Safely overwrite and remove originals after encryption.</li>
        <li><b>Cross-Platform:</b> Works on Windows, Linux, and macOS.</li>
        </ul>

        <h3>User Experience</h3>
        <ul>
         <li><b>GUI:</b> Drag-and-drop interface, password generator, and real-time password strength feedback.</li>
        <li><b>CLI:</b> Command-line support for automation and scripting.</li>
        <li><b>Logging:</b> Detailed logs saved locally for easy troubleshooting.</li>
        </ul>

        <h3>Notes</h3>
        <ul>
        <li>Passwords must meet a minimum strength score for security.</li>
        <li>Key files (up to 1 KB) should be backed up and used consistently.</li>
        <li>Legacy files are detected and decrypted automatically.</li>
        </ul>
        """)
        about_layout.addWidget(about_text)
        help_tabs.addTab(about_widget, "About")
        
        help_layout.addWidget(help_tabs)
        self.tabs.addTab(main_tab, "Main")
        self.tabs.addTab(help_tab, "Help")

        self.setAcceptDrops(True)

    def refresh_logs(self):
        """Load and display the log file contents."""
        try:
            log_path = LOG_FILE_PATH or (Path(os.getenv('APPDATA', Path.home())) / "FileEncryptor" / "file_encryptor.log")
            if os.path.exists(log_path):
                with open(log_path, 'r', encoding='utf-8') as f:
                    self.logs_text.setText(f.read())
            else:
                self.logs_text.setText("Log file not found.")
        except Exception as e:
            self.logs_text.setText(f"Error loading log file: {e}")

    def show_context_menu(self, position):
        menu = QMenu()
        remove_action = menu.addAction("Remove Selected")
        action = menu.exec(self.file_list.mapToGlobal(position))
        if action == remove_action:
            for item in self.file_list.selectedItems():
                self.file_list.takeItem(self.file_list.row(item))

    def add_files(self):
        files, _ = QFileDialog.getOpenFileNames(self, "Select Files")
        for file in files:
            self.file_list.addItem(file)

    def add_folder(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Folder")
        if folder:
            self.file_list.addItem(folder)

    def browse_output_dir(self):
        folder = QFileDialog.getExistingDirectory(self, "Select Output Directory")
        if folder:
            self.output_dir_edit.setText(folder)

    def browse_key_file(self):
        file, _ = QFileDialog.getOpenFileName(self, "Select Key File")
        if file:
            self.key_file_edit.setText(file)

    def update_password_strength(self):
        password = self.password_edit.text()
        result = self.crypto.validate_password(password)
        score = result['score']
        feedback = result['feedback']
        strength = ["Very Weak", "Weak", "Fair", "Strong", "Very Strong"]
        self.strength_label.setText(f"Password Strength: {strength[score] if score >= 0 else 'Invalid'}")
        if feedback.get('warning'):
            self.strength_label.setStyleSheet("color: red;")
        elif score < 3:
            self.strength_label.setStyleSheet("color: orange;")
        else:
            self.strength_label.setStyleSheet("color: green;")

    def dragEnterEvent(self, event: QDragEnterEvent):
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event: QDropEvent):
        for url in event.mimeData().urls():
            path = url.toLocalFile()
            if os.path.exists(path):
                self.file_list.addItem(path)

    def start_operation(self):
        if not self.file_list.count():
            QMessageBox.warning(self, "Error", "No files or folders selected.")
            return
        if not self.output_dir_edit.text():
            QMessageBox.warning(self, "Error", "Output directory not specified.")
            return
        if not os.path.isdir(self.output_dir_edit.text()):
            QMessageBox.warning(self, "Error", "Output directory does not exist.")
            return
        if not self.password_edit.text():
            QMessageBox.warning(self, "Error", "Password is required.")
            return
        input_paths = []
        for i in range(self.file_list.count()):
            path = self.file_list.item(i).text()
            if os.path.isdir(path):
                for root, _, files in os.walk(path):
                    for file in files:
                        input_paths.append(os.path.join(root, file))
            else:
                input_paths.append(path)
        
        operation = 'encrypt' if self.encrypt_radio.isChecked() else 'decrypt'
        self.thread = WorkerThread(
            self.crypto, operation, input_paths, self.output_dir_edit.text(),
            self.password_edit.text(), self.key_file_edit.text() or None, self.shred_check.isChecked())
        self.thread.progress.connect(self.progress_bar.setValue)
        self.thread.status.connect(self.status_label.setText)
        self.thread.finished.connect(self.operation_finished)
        self.start_btn.setEnabled(False)
        self.cancel_btn.setEnabled(True)
        self.thread.start()

    def cancel_operation(self):
        self.cancel_flag[0] = True
        self.status_label.setText("Cancelling...")
        self.cancel_btn.setEnabled(False)

    def operation_finished(self):
        self.cancel_flag[0] = False
        self.start_btn.setEnabled(True)
        self.cancel_btn.setEnabled(False)
        self.progress_bar.setValue(0)
        self.status_label.setText("Operation completed.")
        self.refresh_logs()

    def load_settings(self):
        settings = QSettings("FileEncryptor", "Settings")
        self.output_dir_edit.setText(settings.value("output_dir", ""))
        self.key_file_edit.setText(settings.value("key_file", ""))

    def closeEvent(self, event):
        settings = QSettings("FileEncryptor", "Settings")
        settings.setValue("output_dir", self.output_dir_edit.text())
        settings.setValue("key_file", self.key_file_edit.text())
        event.accept()

def run_cli(args):
    crypto = CryptoEngine()
    success_count = 0
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
    
    password = args.password or getpass.getpass("Enter password: ")
    for input_file in files_to_process:
        rel_path = os.path.relpath(input_file, os.path.dirname(input_file))
        output_path = os.path.join(args.output_dir, rel_path + ('.enc' if not args.decrypt else ''))
        if args.decrypt:
            success = crypto.decrypt_file(input_file, args.output_dir, password, key_file=args.key_file, cli_mode=True)
        else:
            success = crypto.encrypt_file(input_file, output_path, password, key_file=args.key_file, cli_mode=True)
            if success and args.shred:
                crypto.shred_file(input_file)
        if success:
            success_count += 1
    
    print(f"\nOperation complete. {success_count}/{len(files_to_process)} files processed successfully.")

def main():
    setup_logging()
    try:
        parser = argparse.ArgumentParser(description="Secure File and Directory Encryptor.")
        parser.add_argument('input_paths', nargs='*', help="Input files or directories.")
        parser.add_argument('--cli', action='store_true', help="Run in command-line mode.")
        parser.add_argument('-d', '--decrypt', action='store_true', help="Decrypt files.")
        parser.add_argument('-o', '--output-dir', help="Output directory.")
        parser.add_argument('-p', '--password', help="Password (will prompt if not provided).")
        parser.add_argument('-k', '--key-file', help="Optional key file for additional security.")
        parser.add_argument('--shred', action='store_true', help="Securely delete originals after encryption.")
        args = parser.parse_args()
        if args.cli or args.input_paths:
            if not args.input_paths:
                parser.error("At least one input path is required in CLI mode.")
            if not args.output_dir:
                parser.error("--output-dir is required in CLI mode.")
            if not os.path.isdir(args.output_dir):
                parser.error(f"Output directory does not exist: {args.output_dir}")
            if args.key_file and not os.path.exists(args.key_file):
                parser.error(f"Key file does not exist: {args.key_file}")
            run_cli(args)
        else:
            app = QApplication(sys.argv)
            window = FileEncryptor()
            window.show()
            sys.exit(app.exec())
    except Exception as e:
        logging.error(f"A critical error occurred: {e}\n{traceback.format_exc()}")
        try:
            app = QApplication.instance() or QApplication(sys.argv)
            error_box = QMessageBox()
            error_box.setIcon(QMessageBox.Icon.Critical)
            error_box.setText("A critical error occurred.")
            error_box.setInformativeText(f"Please check the log file:\n{LOG_FILE_PATH or 'Console'}\n\nError: {e}")
            error_box.setWindowTitle("Application Error")
            error_box.exec()
        except Exception:
            print(f"A critical error occurred, and the GUI error dialog could not be shown: {e}", file=sys.stderr)
        sys.exit(1)

if __name__ == '__main__':
    main()
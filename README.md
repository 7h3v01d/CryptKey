# CryptKey v2.1.0
### Secure File and Directory Encryptor

A Python application for securely encrypting and decrypting files and directories using AES-256-GCM for encryption, Argon2 for key derivation, and zlib for compression.

### Features

---
Encryption: 
- Encrypt files or directories with AES-256-GCM, preserving folder structures.
- Decryption: Decrypt .enc files, including legacy files without metadata.
- Key File Support: Optional key file (max 1KB) for enhanced security.
- Integrity Check: SHA256 hash verification to ensure decrypted files are uncorrupted.
- Secure Shredding: Overwrite original files multiple times before deletion.
- GUI: Drag-and-drop interface, password strength feedback, and a built-in log viewer.
- CLI: Command-line interface supporting multiple input paths for automation
- Licensing: Free/Personal/Commercial tiers, gated by Ed25519-signed license keys

---
### Installation

1. Ensure Python 3.8+ is installed:
```Bash
python --version
```
Create and activate a virtual environment:
```Bash
python -m venv venv
.\venv\Scripts\activate  # Windows
source venv/bin/activate  # Linux/macOS
```
Install dependencies:
```Bash
pip install -r requirements.txt
```

---
### GUI Usage
Run the application:
```Bash
python file_encryptor_enhanced.py
```
1. **Select Files/Directories:** Use buttons or drag-and-drop files/folders into the list.
2. **Select Output Directory:** Choose where to save processed files.
3. **Enter Password:** Real-time strength feedback is provided.
4. **Choose Operation:** Select "Encrypt" or "Decrypt".
5. **Start Processing:** Click "Start" to begin.

---
### CLI Usage

The CLI supports multiple input paths simultaneously. If -p is omitted, you will be prompted securely.
Encrypt multiple items:
```Bash
python file_encryptor_enhanced.py path/to/file1.txt path/to/folder2/ -o ./output -p password --cli [--shred]
```
Decrypt a file:
```Bash
python file_encryptor_enhanced.py file1.txt.enc -o ./output -p password --cli -d
```
Use a Key File:
```Bash
python file_encryptor_enhanced.py input.txt -o ./output -p password --cli -k key.bin
```
---
### File Format
The application uses a specific binary structure for .enc files to identify versions and ensure integrity:
```text
Component              Size             Description

Magic Number          4 bytes           Hardcoded as ENC1 to identify the new format.

Salt                  16 bytes          Used for Argon2 key derivation.

Nonce                 12 bytes          Initialization vector for AES-GCM.

Header Length         4 bytes           Big-endian length of the encrypted JSON header.

Header                Variable          Encrypted JSON containing original_filename and sha256.

Ciphertext            Variable          zlib-compressed file content, encrypted with AES-256-GCM.

Tag                   16 bytes          AES-GCM authentication tag for integrity verification.
```
Note: Legacy files omit the Magic Number and Header components. They are automatically detected and saved as decrypted_<filename>

---
## Testing
The test suite uses pytest and lives in `src/tests/`. From the `src/` directory:
```bash
pip install pytest
python -m pytest
```
This runs 48 tests covering the crypto engine (encrypt/decrypt round trips,
legacy format, tamper/corruption handling, key derivation), the Ed25519
license engine (signing, verification, expiry, machine locking, tamper
detection), and the app's license integration. Qt tests run headless via the
`offscreen` platform plugin automatically (no display required).

---
### Logging

Logs are saved locally for troubleshooting:
- Windows: %APPDATA%\FileEncryptor\file_encryptor.log
- Linux/macOS: ~/.local/share/FileEncryptor/file_encryptor.log

---
### Licensing Setup
`file_encryptor_enhanced.py` verifies license keys with an embedded Ed25519
public key (`LICENSE_PUBLIC_KEY`). A vendor keypair has already been
generated and its public half is embedded in the source, so license
verification is live.

The **private** half (`keystore/vendor.key` in this delivery) is what
`cryptkey_license_generator.py` needs to sign new license keys. The
generator GUI always reads/writes its keystore at a fixed path —
`~/.local/share/CryptKey/vendor.key` on Linux/macOS (it does not currently
check `%APPDATA%` on Windows, unlike the main app's logging setup — worth
fixing if you'll run the generator on Windows). To issue licenses from the
generator, copy `keystore/vendor.key` and `keystore/vendor.pub.json` into
that folder and unlock them with the master password below.

**Master password:** `feDKTh%eXtqZHZoe^lTW` — store this somewhere safe
(e.g. a password manager) and rotate it by regenerating a keypair if it's
ever exposed. Never commit `vendor.key` to source control or bundle it into
the built app. If you lose or rotate it, run the generator to create a new
keypair and re-embed the new public key in `file_encryptor_enhanced.py`,
which will invalidate any previously issued licenses.

---
### Notes
- **Password Strength**: Passwords must score 3/4 or higher (via zxcvbn).
- **Key File**: Enhances security but must be used consistently for encryption/decryption.
- **Legacy Files**: Automatically detected and decrypted (named `decrypted_<filename>`).
- **Shredding**: Permanently deletes originals with multiple random overwrites.

---
## Contributing
Submit issues or pull requests to the repository (TBD).

---
## License
MIT License. See source code for details.


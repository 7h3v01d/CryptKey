# CryptKey
### Secure File and Directory Encryptor

A Python application for securely encrypting and decrypting files and directories using AES-GCM for encryption, Argon2 for key derivation, and zlib for compression. Features include a user-friendly GUI, CLI support, secure file shredding, password strength checking, key file support, and integrity verification.

## Features
- **Encryption**: Encrypt files or directories with AES-256-GCM, preserving folder structures.
- **Decryption**: Decrypt `.enc` files, including legacy files without metadata.
- **Key File Support**: Optional key file for enhanced security.
- **Integrity Check**: SHA256 hash verification to ensure decrypted files are uncorrupted.
- **Secure Shredding**: Overwrite original files multiple times before deletion.
- **GUI**: Drag-and-drop interface, password generation, and real-time strength feedback.
- **CLI**: Command-line interface for scripting and automation.
- **Logging**: Detailed logs in `%APPDATA%\FileEncryptor\file_encryptor.log` (Windows) or `~/.local/share/FileEncryptor/file_encryptor.log` (Linux/macOS).
- **Cross-Platform**: Works on Windows, Linux, and macOS.

## Installation
1. Ensure Python 3.8+ is installed:
   ```bash
   python --version
   ```
2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   .\venv\Scripts\activate  # Windows
   source venv/bin/activate  # Linux/macOS
   ```
3. Install dependencies:
   ```bash
   pip install PyQt6 cryptography argon2-cffi zxcvbn tqdm
   ```

## GUI Usage
Run the application:
```bash# CryptKey v1.6.0
### Secure File and Directory Encryptor

A Python application for securely encrypting and decrypting files and directories using AES-256-GCM for encryption, Argon2 for key derivation, and zlib for compression2.

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
pip install PyQt6 cryptography argon2-cffi zxcvbn tqdm
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

Salt                  16 bytes          Used for Argon2 key derivation15.

Nonce                 12 bytes          Initialization vector for AES-GCM16.

Header Length         4 bytes           Big-endian length of the encrypted JSON header17.

Header                Variable          Encrypted JSON containing original_filename and sha25618.

Ciphertext            Variable          zlib-compressed file content, encrypted with AES-256-GCM19.

Tag                   16 bytes          AES-GCM authentication tag for integrity verification20.
```
Note: Legacy files omit the Magic Number and Header components. They are automatically detected and saved as decrypted_<filename>

---
## Testing
Run the unit tests to verify functionality:
```bash
python -m unittest test_file_encryptor_enhanced.py
```

---
### Logging

Logs are saved locally for troubleshooting:
- Windows: %APPDATA%\FileEncryptor\file_encryptor.log
- Linux/macOS: ~/.local/share/FileEncryptor/file_encryptor.log

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


python file_encryptor_enhanced.py
```

1. **Select Files/Directories**: Use the "Select Files/Dirs" button or drag-and-drop files/folders.
2. **Select Output Directory**: Choose where to save encrypted/decrypted files.
3. **Enter Password**: Type a password or click "Generate Secure Password" to create one.
4. **Select Key File (Optional)**: Choose a key file for additional security.
5. **Choose Operation**: Select "Encrypt" or "Decrypt".
6. **Shred Option**: Enable "Securely delete originals after encryption" to shred source files (with confirmation).
7. **Start Processing**: Click "Start Processing" to begin.

## CLI Usage
- **Encrypt a file**:
  ```bash
  python file_encryptor_enhanced.py input_file -o output_dir -p password --cli [--shred] [--key-file key.bin]
  ```
- **Encrypt a directory**:
  ```bash
  python file_encryptor_enhanced.py input_dir -o output_dir -p password --cli [--shred] [--key-file key.bin]
  ```
- **Decrypt a file**:
  ```bash
  python file_encryptor_enhanced.py input_file.enc -o output_dir -p password --cli -d [--key-file key.bin]
  ```
- **Password Prompt**: If `-p` is omitted, you’ll be prompted for a password securely.
- **Key File**: Use `-k key.bin` to include a key file (max 1KB).

## File Format
Encrypted files (`.enc`) have the following structure:
- **Salt**: 16 bytes (Argon2 key derivation).
- **Nonce**: 12 bytes (AES-GCM).
- **Header Length**: 4 bytes (big-endian, length of JSON header).
- **Header**: JSON metadata (`original_filename`, `sha256` hash), encrypted.
- **Ciphertext**: zlib-compressed file content, encrypted with AES-256-GCM.
- **Tag**: 16 bytes (AES-GCM authentication tag).

Legacy files (from older versions) omit the header length and JSON header, containing only salt, nonce, ciphertext, and tag.

## Testing
Run the unit tests to verify functionality:
```bash
python -m unittest test_file_encryptor_enhanced.py
```

## Logging
Logs are saved to:
- Windows: `%APPDATA%\FileEncryptor\file_encryptor.log`
- Linux/macOS: `~/.local/share/FileEncryptor/file_encryptor.log`

## Notes
- **Password Strength**: Passwords must score 3/4 or higher (via zxcvbn).
- **Key File**: Enhances security but must be used consistently for encryption/decryption.
- **Legacy Files**: Automatically detected and decrypted (named `decrypted_<filename>`).
- **Shredding**: Permanently deletes originals with multiple random overwrites.

## License
MIT License. See source code for details.

## Contributing
Submit issues or pull requests to the repository (TBD).
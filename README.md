# CryptKey v1.6.0
### Secure File and Directory Encryptor

⚠️ **LICENSE & USAGE NOTICE — READ FIRST**

This repository is **source-available for private technical evaluation and testing only**.

- ❌ No commercial use  
- ❌ No production use  
- ❌ No academic, institutional, or government use  
- ❌ No research, benchmarking, or publication  
- ❌ No redistribution, sublicensing, or derivative works  
- ❌ No independent development based on this code  

All rights remain exclusively with the author.  
Use of this software constitutes acceptance of the terms defined in **LICENSE.txt**.

---

## Overview

**CryptKey** is a Python-based application for securely encrypting and decrypting files and directories using modern cryptographic primitives.

The project is published **solely for evaluation and showcase purposes**, demonstrating cryptographic design, secure file handling, and GUI/CLI tooling. It is **not** released as open-source software.

---

## Features

### Encryption & Security
- Encrypt files and directories using **AES-256-GCM**
- Preserve directory structures during encryption
- **Argon2** key derivation for password hardening
- Optional **key file** support (≤ 1 KB) for multi-factor protection
- **SHA-256 integrity verification** on decryption
- Secure shredding with multi-pass overwrite before deletion

### Usability
- Drag-and-drop **GUI interface**
- Real-time **password strength feedback**
- Built-in log viewer
- Full **CLI support** for automation and scripting
- Supports multiple input paths in a single operation

---

## Requirements

- Python **3.8+**
- PyQt6
- cryptography
- argon2-cffi
- zxcvbn
- tqdm

---

## Installation (Evaluation Use Only)

Verify Python version:
```bash
python --version
```
Create and activate a virtual environment:
```bash
python -m venv venv
```
```bash
.\venv\Scripts\activate      # Windows
```
```bash
source venv/bin/activate    # Linux / macOS
```
Install dependencies:
```bash
pip install PyQt6 cryptography argon2-cffi zxcvbn tqdm
```
---

## GUI Usage

Run the application:
```bash
python file_encryptor_enhanced.py
```
Workflow:

1. Select files or directories (buttons or drag-and-drop)
2. Select output directory
3. Enter password (strength feedback provided)
4. Choose operation: Encrypt or Decrypt
5. Click Start to begin processing

---

## CLI Usage

The CLI supports multiple input paths.</br>
If -p is omitted, you will be prompted securely.

### Encrypt multiple items
```bash
python file_encryptor_enhanced.py path/to/file1.txt path/to/folder2/ \
  -o ./output -p password --cli [--shred]
```
### Decrypt a file
```bash
python file_encryptor_enhanced.py file1.txt.enc -o ./output -p password --cli -d
```
### Use a key file
```bash
python file_encryptor_enhanced.py input.txt -o ./output -p password --cli -k key.bin
```
## Encrypted File Format

CryptKey uses a structured binary format to ensure versioning, integrity, and backward compatibility.
```text
Component        Size        Description
---------------------------------------------------------------
Magic Number     4 bytes     Fixed value: ENC1 (new format)
Salt             16 bytes    Argon2 key derivation salt
Nonce            12 bytes    AES-GCM initialization vector
Header Length    4 bytes     Big-endian encrypted header length
Header           Variable    Encrypted JSON (filename, SHA-256)
Ciphertext       Variable    zlib-compressed, AES-GCM encrypted data
Auth Tag         16 bytes    AES-GCM authentication tag
```
Legacy files omit the Magic Number and Header fields.</br>
They are automatically detected and decrypted as decrypted_<filename>.

## Logging

Logs are stored locally for diagnostic and evaluation purposes:

- Windows: %APPDATA%\FileEncryptor\file_encryptor.log
- Linux/macOS: ~/.local/share/FileEncryptor/file_encryptor.log

---

## Contribution Policy

Feedback, bug reports, and suggestions are welcome.

You may submit:

- Issues
- Design feedback
- Pull requests for review

However:

- Contributions do not grant any license or ownership rights
- The author retains full discretion over acceptance and future use
- Contributors receive no rights to reuse, redistribute, or derive from this code

---

License
This project is not open-source.

It is licensed under a private evaluation-only license.
See LICENSE.txt for full terms.

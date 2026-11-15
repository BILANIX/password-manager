# Web-Based Secure Password Manager — Checkpoint 2

## Overview

This Flask application provides account authentication, a browser-encrypted password vault, and server-side encrypted file storage.

### Implemented functionality

- Account registration and login. Account master passwords are hashed with Argon2id (`argon2-cffi`); plaintext account passwords are not stored.
- Session management with HttpOnly, SameSite=Strict, Secure cookies and a 30-minute session lifetime.
- CSRF protection for HTML forms and JavaScript API requests.
- Login rate limiting (5 POST attempts per minute per client address).
- Browser-side password-vault encryption using AES-256-GCM. Each entry has a random salt and IV; the browser derives its key using PBKDF2-HMAC-SHA-256 (600,000 iterations). The server stores the encrypted payload and does not receive the vault encryption password.
- Server-side file encryption and decryption. Uploaded files (up to 10 MB) are encrypted with Fernet before being written to the application's private storage directory. Downloading a file requires an authenticated session and decrypts it on the server.
- Per-user access control for vault entries and uploaded files.
- Basic security response headers and SQLite persistence.

## Important security notes

The account login password uses Argon2id. The separate browser vault key currently uses PBKDF2-HMAC-SHA-256, not Argon2id; this is disclosed rather than presented as Argon2id. The browser-encrypted vault and server-encrypted file storage are separate features with different trust models.

The server-side file-encryption key is created at `instance/.file_encryption_key` and is required to decrypt uploaded files. Keep this file private and back it up securely. If it is lost, encrypted files cannot be recovered. The key is stored separately from the encrypted files but on the same application host, so this is at-rest protection, not protection against a fully compromised server.

The development server uses HTTPS with a temporary self-signed certificate. The browser will show a certificate warning on first visit; this is expected for local development. This prototype is for coursework and should not be used to store real credentials.

## Run on macOS or Linux

Python 3.10 or newer is recommended.

```bash
cd password-manager
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python app.py
```

Open **https://127.0.0.1:5000**. Accept the browser's local self-signed-certificate warning to access the development application.

On first start, the application creates the `instance/` directory, the SQLite database, a persistent Flask secret key, and a persistent file-encryption key. Do not delete the two key files if you need to retain existing sessions or decrypt previously uploaded files.

## Main application flow

1. Register with a username and a master password of at least 12 characters.
2. Log in to open the vault.
3. Add a password entry and choose a separate vault encryption password. The entry is encrypted in the browser before it is sent to the server.
4. Enter the same vault encryption password to decrypt and view a saved entry. Entries can also be deleted.
5. In **Encrypted file storage**, upload a file (maximum 10 MB). The server encrypts it before saving it. Use **Decrypt & download** to retrieve the original file.
6. Log out using the navigation link.

## Dependencies

All Python dependencies are listed in `requirements.txt`. No external database server or database GUI is required; the application uses SQLite.

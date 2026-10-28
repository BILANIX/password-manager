# Web-Based Password Manager — Checkpoint 2

## Current Implementation

- Flask web application with an SQLite database.
- Account registration and login.
- Account master passwords hashed using Argon2id through `argon2-cffi`.
- Session cookies configured with `HttpOnly` and `SameSite=Strict`, with a 30-minute session lifetime.
- Stable Flask secret key stored locally in `instance/.flask_secret_key`, with restrictive file permissions.
- Browser-side vault encryption using AES-256-GCM before encrypted entries are sent to the server.
- Browser-side vault-key derivation using Argon2id, with time cost 3, memory cost 64 MiB, and parallelism 1.
- Random salt and 96-bit nonce for vault encryption.
- Backward compatibility for entries encrypted using the earlier PBKDF2-SHA256 key-derivation implementation.
- Server-side storage of encrypted vault payloads rather than plaintext vault entry contents.
- User-specific authorization checks when listing, saving, and deleting vault entries.
- CSRF protection for forms and state-changing requests.
- Login rate limiting of five POST requests per minute.
- Security response headers, including Content Security Policy, `X-Content-Type-Options`, `X-Frame-Options`, and `Referrer-Policy`.
- Locally bundled browser-side Argon2 library at `static/js/argon2-bundled.min.js`.
- SQLite foreign-key enforcement for application database connections.

## Security Design

Account authentication and vault encryption serve different purposes.

The account master password is hashed using Argon2id on the server for login verification. Vault entries are encrypted in the browser using AES-256-GCM, with a key derived from the vault encryption password using Argon2id.

The browser sends the encrypted payload to Flask. The server stores this payload and does not need the plaintext vault entry contents to save or delete entries.

Vault entries are associated with individual user accounts, and database queries restrict access to the authenticated user's entries.

The application uses CSRF protection, login rate limiting, session cookie security settings, and security response headers to provide additional protection.

## Local Development

The development server uses HTTP on localhost. `SESSION_COOKIE_SECURE=False` is intended only for local HTTP development. A deployed HTTPS application should enable secure cookies and use an appropriate production configuration.

The Flask development server currently uses debug mode. Debug mode must be disabled before deployment.

The rate limiter currently uses in-memory storage. This is sufficient for local development and demonstration, but a deployed application should use a suitable persistent or shared storage backend.

This project is a coursework prototype, not a production-ready password manager.

## Run on macOS

```bash
cd ~/password-manager
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python app.py
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000).

## Test Flow

1. Register an account using a username and account master password of at least 12 characters.
2. Log in using the account credentials.
3. Enter a vault encryption password, fill in a test entry, and click **Encrypt and save**.
4. Confirm that the vault displays the encrypted payload rather than the original entry contents.
5. Enter the same vault encryption password and click **Decrypt** to verify that the entry can be decrypted.
6. Delete the test entry.
7. Log out and confirm that the vault requires authentication.
8. Restart the application and confirm that the account and stored data remain available.

Use fake credentials when testing.

## Remaining Improvements

- Add automated tests for authentication, authorization, encryption-related workflows, and error handling.
- Improve error handling and logging.
- Prepare and test a production deployment configuration with HTTPS, secure cookies, debug mode disabled, and an appropriate rate-limit storage backend.
- Review the complete application for additional security and usability improvements.

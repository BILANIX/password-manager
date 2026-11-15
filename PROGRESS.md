# Checkpoint 2 — Progress note

The Checkpoint 2 prototype includes a Flask web interface, SQLite-backed account and vault storage, Argon2id password hashing, session management, CSRF protection, login rate limiting, and HTTPS for local development. Password-vault entries are encrypted in the browser with AES-256-GCM before storage. A separate file-storage flow encrypts uploaded files on the server and decrypts them only for authenticated downloads.

The implementation uses a persistent local Flask secret key and file-encryption key. Run instructions and dependency declarations are provided in `README.md` and `requirements.txt`.

Known limitation: browser-side vault-key derivation currently uses PBKDF2-HMAC-SHA-256 (600,000 iterations), while the account login password is hashed with Argon2id. The server-side file-encryption key is held on the application host, so the file feature protects stored files at rest but does not protect them from a fully compromised host. This is a coursework prototype, not a production password manager.

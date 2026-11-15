# Checkpoint 3 — Progress note

The application builds on the Checkpoint 2 Flask password-manager prototype.

## Implemented security controls

- Global CSRF protection for state-changing requests.
- Argon2id hashing for account login passwords.
- Browser-side AES-256-GCM encryption for vault entries.
- Fernet encryption for uploaded files at rest.
- Per-user access control for vault entries and uploaded files.
- Username allowlist validation.
- Parameterized SQLite queries in the tested operations.
- Session cookie security settings and security response headers.
- Login rate limiting.
- Structured JSON security logging and generic error handling.

## Security testing

The recorded Checkpoint 3 tests include:

- Seven CSRF rejection tests.
- Seven cross-user access-control tests.
- SQL injection login test.
- XSS output-escaping test.
- Three username validation tests.
- Error handling and security logging checks.

See `docs/checkpoint3-security-evidence.md` for test details, results, and limitations.

## Known limitations

- The browser vault key derivation uses PBKDF2-HMAC-SHA-256 with 600,000 iterations, not Argon2id. Account login passwords use Argon2id.
- Flask-Limiter currently uses in-memory storage, which is not suitable for production deployment.
- Uploaded files are encrypted server-side with a key stored on the application host. This protects files at rest but not against a fully compromised host.
- The documented security checks are coursework-level tests.

# Checkpoint 3 — Security Test Evidence

## 1. Purpose

This document records security checks performed on the Flask password-manager application for Checkpoint 3. Tests were executed against isolated temporary application instances where possible, to avoid modifying the existing application database, encryption keys, or user data.

## 2. Test results

### 2.1 CSRF protection

Flask-WTF global CSRF protection is enabled. HTML forms include CSRF tokens, and JavaScript vault API requests send the token in the `X-CSRFToken` header.

Requests were sent without CSRF tokens, using a valid HTTPS base URL and Referer header.

| Test | Expected result | Actual result |
|---|---|---|
| Registration POST without token | HTTP 400 | PASS — HTTP 400 |
| Login POST without token | HTTP 400 | PASS — HTTP 400 |
| Vault entry creation POST without token | HTTP 400 | PASS — HTTP 400 |
| Vault entry deletion DELETE without token | HTTP 400 | PASS — HTTP 400 |
| File upload POST without token | HTTP 400 | PASS — HTTP 400 |
| File deletion POST without token | HTTP 400 | PASS — HTTP 400 |
| Logout POST without token | HTTP 400 | PASS — HTTP 400 |

**Result: 7/7 tests passed.**

### 2.2 Cross-user access control

Two separate test accounts, Alice and Bob, were created in an isolated application instance. Alice created a vault entry and uploaded an encrypted file. Bob then attempted to access Alice's resources.

| Test | Expected result | Actual result |
|---|---|---|
| Alice creates a vault entry | Entry created | PASS |
| Bob views Alice's vault entry | Entry not visible | PASS |
| Bob deletes Alice's vault entry | Access denied | PASS — HTTP 404 |
| Alice uploads an encrypted file | Upload succeeds | PASS — HTTP 302 redirect |
| Bob downloads Alice's file | Access denied | PASS — HTTP 404 |
| Bob deletes Alice's file | Access denied | PASS — HTTP 404 |
| Alice's encrypted file after Bob's attempts | File remains intact | PASS |

**Result: 7/7 tests passed.**

The application scopes vault and file operations to the authenticated user's ID. Unauthorized resource access returns HTTP 404 in the tested cases.

### 2.3 SQL injection

A login attempt using the SQL injection payload `' OR 1=1 --` was tested.

- Normal registration succeeded.
- The SQL injection login attempt did not bypass authentication.

**Result: PASS.**

The tested login query uses a parameterized SQLite statement. This test demonstrates resistance to the tested login injection payload; it is not a substitute for a complete audit of every database query.

### 2.4 Cross-site scripting (XSS)

A username containing `<script>alert(1)</script>` was submitted in an isolated test instance.

- The original XSS test confirmed that Jinja rendered the username as escaped HTML.
- The raw script element was not present in the rendered output.
- Browser-side vault output uses `textContent` rather than assigning untrusted values through `innerHTML`.
- A subsequent input-validation test confirmed that script-containing usernames are now rejected.

**Result: PASS for the tested output-escaping and input-validation cases.**

### 2.5 Input validation

The registration endpoint was tested after adding a username allowlist.

Allowed usernames must contain 3–80 ASCII letters, numbers, periods, underscores, or hyphens.

| Input | Expected result | Actual result |
|---|---|---|
| `alice_01` | Accepted | PASS — HTTP 302 |
| `<script>alert(1)</script>` | Rejected | PASS — HTTP 200 |
| `alice@admin` | Rejected | PASS — HTTP 200 |

**Result: 3/3 tests passed.**

### 2.6 Error handling and security logging

Runtime checks confirmed:

- Unknown routes return HTTP 404.
- Requests without CSRF tokens return HTTP 400.
- A simulated internal server error returns HTTP 500 without exposing the test exception message to the client.
- Security events are written to `instance/security.log` in structured JSON format.
- The security log file was created with file permissions `0600`.

**Result: PASS for the tested error-handling and logging checks.**

### 2.7 Application functionality and encryption

Earlier isolated smoke tests verified the following Checkpoint 2 functionality remained operational:

- Registration and login.
- Authenticated vault access.
- Vault entry creation and deletion.
- File upload and download.
- Encrypted file storage.
- Logout and unauthenticated access redirection.
- Security headers and session cookie attributes.
- Private permissions on the file-encryption key.

**Result: PASS for the previously executed smoke tests.**


### 2.8 Login rate limiting

The login endpoint was tested with six consecutive failed login attempts from the same client address.

| Test | Expected result | Actual result |
|---|---|---|
| First failed login attempt | Processed, not rate-limited | PASS — HTTP 200 |
| Attempts two through five | Processed, not rate-limited | PASS — HTTP 200 |
| Sixth failed login attempt | Rate-limited | PASS — HTTP 429 |

**Result: 3/3 checks passed.**

The test confirms the configured threshold of five POST attempts per minute. Flask-Limiter emitted a warning because the application currently uses in-memory storage; this is documented as a production limitation.

## 3. Security controls implemented

- Global CSRF protection using Flask-WTF.
- Parameterized SQLite queries in the tested authentication and data-access operations.
- Argon2id hashing for account login passwords.
- Browser-side AES-256-GCM encryption for vault entries.
- Fernet encryption for uploaded files at rest.
- Per-user access checks for vault and file operations.
- Username allowlist validation.
- Jinja template autoescaping and safe DOM text insertion.
- Login rate limit configured to five POST attempts per minute.
- HttpOnly, Secure, SameSite=Strict session cookies.
- Security response headers and a Content Security Policy.
- Structured security event logging and generic error responses.
- Maximum uploaded file size of 10 MB.

## 4. Limitations and further work

- Flask-Limiter currently uses in-memory storage. The warning about this configuration is expected in local development; a persistent backend should be configured for production.
- The login rate-limit threshold was tested using six failed login attempts from the same client address. The first five returned HTTP 200 and the sixth returned HTTP 429, confirming the configured limit of five POST attempts per minute.
- The SQL injection test covered a login payload. A full audit and broader payload testing across all database operations remain advisable.
- The vault encryption key derivation currently uses PBKDF2-HMAC-SHA-256 with 600,000 iterations, not Argon2id. Account login passwords use Argon2id. These are separate mechanisms.
- Uploaded files are encrypted on the server using a key stored on the application host. This provides protection at rest but does not protect against a fully compromised host.
- The checks documented here are coursework-level tests, not a production security certification.

## 5. Conclusion

The tested implementation demonstrates working CSRF rejection, per-user access control for vault entries and uploaded files, resistance to the tested SQL injection and XSS cases, username input validation, structured security logging, and generic error handling. The remaining limitations are documented above and should be considered before any production deployment.

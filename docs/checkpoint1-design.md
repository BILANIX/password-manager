
# Week 4 Checkpoint 1 – Threat Model and Architecture

## System Overview

This project is a secure web-based password manager built with Flask and SQLite. The browser derives an encryption key from the user's master password using Argon2id. Password entries are encrypted with AES-256-GCM before being stored.

## System Architecture

Browser → HTTPS → Flask Application → SQLite Database

### Trust Boundaries

- Browser ↔ Web Application
- Web Application ↔ Database

### Encryption

- Master password is never stored in plaintext.
- Encryption key is derived using Argon2id.
- Password entries are encrypted using AES-256-GCM before storage.

## Threat Model

| Threat                  | OWASP Top 10 | Mitigation                         |
|-------------------------|--------------|------------------------------------|
| SQL Injection           | A03          | Prepared statements                |
| Cross-Site Scripting    | A03          | Output encoding                    |
| CSRF                    | A01          | CSRF tokens                        |
| Broken Authentication   | A07          | Secure sessions                    |
| Session Fixation        | A07          | Regenerate session ID              |
| Session Hijacking       | A07          | HttpOnly, Secure, SameSite cookies |
| Brute Force             | A07          | Rate limiting                      |
| Sensitive Data Exposure | A02          | HTTPS and AES encryption           |

## Cryptographic Design

### Key Derivation

The master password is processed with Argon2id to derive a 256-bit encryption key.

### Encryption

AES-256-GCM is used to encrypt password entries before they are stored.

### Database Stores

- username
- password hash
- salt
- encrypted vault entries
- IV/Nonce

## Authentication and Session Model

| Feature                     | Decision              |
|-----------------------------|-----------------------|
| Session storage             | Server-side           |
| Cookie                      | HttpOnly              |
| Secure                      | Yes                   |
| SameSite                    | Strict                |
| Session expiry              | 30 minutes inactivity |
| Session fixation prevention | Regenerate session ID |
| Logout                      | Destroy session       |
| MFA                         | Optional TOTP         |
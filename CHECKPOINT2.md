# Checkpoint 2 progress — Web-Based Secure Password Manager

**Course:** ICS0027 — Web Application Security

## Implemented

The Checkpoint 1 Flask scaffold now supports account registration, login with a master passphrase, logout and an authenticated vault. Users can create, list, view, update and delete their own entries. Each entry contains a title, website URL, username, password and optional notes.

Master passwords are verified using salted Argon2id hashes. A separate random KDF salt derives each user's vault key. Entry JSON is encrypted on the server using AES-256-GCM; updates get a new nonce, and authenticated additional data binds each record to its owner, entry ID and format version. SQLite receives encrypted payloads and account metadata, never plaintext entry fields or vault keys.

Opaque sessions are stored in RAM. The cookie contains a random token with Secure, HttpOnly and SameSite=Strict attributes. Login rotates session and CSRF tokens; logout, idle/absolute expiry and restart invalidate sessions. POST requests require CSRF tokens. Owner checks, parameterized SQL, input limits, autoescaping, security headers, login throttling and a KDF concurrency limit are implemented.

The development server runs on loopback HTTPS with a locally trusted mkcert certificate. Setup and test commands are in README.md and docs/DEVELOPMENT.md.

## Requirements and interpretation

| Checkpoint requirement | Implementation |
| --- | --- |
| Working web interface and core flows | Registration, login/logout and complete vault CRUD |
| Server-side encryption/decryption | Encrypted entry JSON stored in SQLite, matching the Password Manager design |
| Password hashing and secure sessions | Argon2id; RAM sessions; cookie flags; rotation, expiry and revocation |
| TLS in development | Local HTTPS certificate and Flask TLS endpoint |
| Clean-machine instructions and progress history | Pinned requirements, setup guide and three implementation stages |

The assignment's file-encryption wording appears under both project options. This implementation encrypts password-manager entry payloads. It does not encrypt the entire SQLite file or introduce uploads, which the design excludes.

## Validation evidence

- OS and Python version: Arch Linux and 3.14.8 Python 
- Dependency installation and pip check: Dependencies installed; pip check passed (No broken requirements found) 
- Tests (`Ran 24 tests`, `OK`): 24 tests passed (OK)
- KDF verification / derivation / combined mean: verification - 0.0191s; derivation - 0.0188s; combined - 0.0379s
- Browser opens HTTPS without a certificate warning: Passed
- Register, login, add, view, edit, delete and logout: Passed
- Second account cannot access the first account's entry: Passed
- Restart logs the user out; entries remain available after login: Passed
- GitHub repository URL: https://github.com/Dasiso228/ICS0027-Web-Application-Security

## Remaining scope and limitations

Public deployment with Nginx/Gunicorn, certificate renewal and operational hardening are not part of this development checkpoint. The session design supports one process. Sharing, uploads, import/export, recovery, master-password changes, password generation, MFA and an admin interface are not implemented. A compromised running server/browser can read unlocked credentials. Python does not guarantee full memory erasure. Database metadata remains visible, and offline master-password guessing remains possible.


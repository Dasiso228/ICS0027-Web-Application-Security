# Web-Based Secure Password Manager

ICS0027 — Web Application Security. Checkpoint 2 implements the core web flows from the [Checkpoint 1 design](docs/Checkpoint1_Design.pdf).

## Implemented scope

Users register with a login name and master passphrase, then add, list, view, edit and delete their own website credentials. An entry contains a title, HTTP/HTTPS website URL, saved username, saved password and optional notes. Registration signs the new user in. Logout invalidates the server-side session.

This is a course project: use fictional credentials during development. Sharing, uploads, import/export, browser extensions, password generation, master-password changes, recovery, MFA and an admin interface are outside this checkpoint.

## Run on a clean machine

Python 3.11+ is required. From the repository root on Arch Linux:

```sh
sudo pacman -Syu --needed python python-pip git mkcert nss
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements.txt
.venv/bin/python -m pip check
mkdir -p certs
chmod 700 certs
mkcert -install
mkcert -cert-file certs/localhost.pem -key-file certs/localhost-key.pem localhost 127.0.0.1
chmod 600 certs/localhost-key.pem
.venv/bin/python -m flask --app app --no-debug run --host 127.0.0.1 --port 5443 --cert certs/localhost.pem --key certs/localhost-key.pem --no-debugger --no-reload
```

Open <https://localhost:5443/>. Restart the browser after CA installation if needed. Do not bypass certificate warnings. See [development instructions](docs/DEVELOPMENT.md) for certificate checks and troubleshooting. The same project commands work in fish without activating the virtual environment. Package installation commands target Arch; other systems need their equivalent Python and mkcert installation.

No separate database initialization command is needed. `instance/vault.sqlite3` is created on startup and survives a restart. To make a backup, stop the server and copy the private `instance` directory to a protected location; do not commit it. There are no default accounts or credentials.

## Security design

- Authentication: Argon2id v19, 65,536 KiB, 3 iterations, parallelism 4, 32-byte output and random 16-byte salt. Master passphrases are 15–128 characters, at most 512 UTF-8 bytes; spaces are preserved. Login names use 3–64 ASCII letters, digits, `.`, `_` or `-` and are normalized to lowercase.
- Encryption: a separate random 16-byte KDF salt derives an AES-256 key from the master passphrase. The login hash is not the encryption key. Each entry's complete JSON payload is encrypted with AES-256-GCM, a fresh 12-byte nonce and AAD `user_id:entry_id:format_version`. Ciphertext includes the 16-byte authentication tag. Record IDs are allocated inside the write transaction before encryption.
- Persistence: SQLite stores account names, password hashes, salts, KDF parameters, IDs, owner relationships and encrypted payloads. The whole SQLite file is not encrypted. No plaintext entry fields or vault keys are written to it. Parameterized queries constrain read/update/delete by both entry and owner ID.
- Sessions: random opaque 32-byte tokens identify records in one process's RAM. Only a token is in the `pm_session` cookie: Secure, HttpOnly, SameSite=Strict, Path=/, no Domain and authenticated Max-Age=3600. Passwords are not retained in sessions. Login and registration rotate the session and CSRF token. Logout revokes the token. Server-side expiry is 15 minutes idle or one hour absolute; anonymous form sessions last at most 15 minutes. A background task purges expired state every 60 seconds. Restart invalidates all sessions.
- Request handling: session-bound CSRF tokens on every POST, 64 KiB request limits, field limits from the design, Jinja autoescaping and a restrictive CSP. Website URLs are displayed as text and never fetched by the server. No JavaScript is needed. HTTP and unexpected Host headers are rejected; responses use no-store, nosniff, no-referrer, frame denial and an HTTPS HSTS header.
- Resource controls: five failed credential checks per account and IP per five minutes; at most two concurrent KDF operations; at most 1,024 live sessions and 4,096 throttle keys. State is process-local and resets on restart. Audit events use fixed event names, user IDs where known and outcomes; no passwords, keys, cookie tokens or vault fields are logged.

The assignment repeats “server-side file encryption and decryption” in both project options. This password-manager implementation follows the design's encrypted SQLite entry payloads. It does not add a file-upload/encryption interface or claim whole-database-file encryption.

The browser receives decrypted credentials when an authenticated user views or edits an entry. The “Show saved password” disclosure hides it visually until opened; it is already in that page's HTML. This is server-side encryption, not a zero-knowledge design. A compromised running server or browser can access unlocked secrets. Python cannot guarantee complete physical memory erasure. Deleted or rolled-back database copies are not prevented by AES-GCM.

## Routes

| Methods | Route | Purpose |
| --- | --- | --- |
| GET | `/`, `/health` | Home and health |
| GET, POST | `/register` | Registration |
| GET, POST | `/login` | Authentication and unlock |
| POST | `/logout` | Revoke session |
| GET | `/vault` | List own entry titles and URLs |
| GET, POST | `/vault/new` | Create encrypted entry |
| GET | `/vault/<int:entry_id>` | View owned entry |
| GET, POST | `/vault/<int:entry_id>/edit` | Update owned entry |
| POST | `/vault/<int:entry_id>/delete` | Delete owned entry with confirmation |

## Validation

```sh
.venv/bin/python -m unittest discover -s tests -v
.venv/bin/python -m tools.benchmark_kdf
```

The suite contains 24 tests covering cryptography, storage, authentication, CRUD, isolation between users, CSRF, XSS escaping, SQL injection attempts, cookie flags and rotation, logout/restart invalidation, idle and absolute expiry, rate limiting, KDF capacity, request limits, Host/HTTPS checks and secret-free audit events. Tests use temporary databases and do not modify the real vault. Fake clocks test expiry without waiting an hour; production Argon2 parameters are used.


See [CHECKPOINT2.md](CHECKPOINT2.md) for the progress note and local verification record. The development TLS endpoint is Flask on loopback; Nginx/Gunicorn and public trusted-certificate deployment remain planned work.

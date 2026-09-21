# Web-Based Secure Password Manager

ICS0027 - Web Application Security. Checkpoint 1: threat model and architecture.

## Scope

A small web application where registered users manage their own website credentials. Planned features are registration, login with a master password, listing, adding, viewing, editing and deleting vault entries, and logout. Each entry contains a title, website URL, username, password and optional notes. Credentials will be encrypted on the server before being written to SQLite.

The first version will have no sharing, browser extension, attachments, import, export, password recovery or admin interface. MFA is optional in the assignment and is deferred. This is a learning project; use fictional credentials during development.

## Current state

Implemented: a runnable Flask application, a starting page, a health endpoint, local host restrictions, basic response security headers and this documentation.

Planned: database access, authentication, server-side sessions, encryption, vault operations, CSRF tokens, rate limiting and HTTPS deployment. These security controls are described in the design; they are not implemented by this scaffold. No passwords or other user data can be saved yet. No session cookies are created.

## Design and stack

Read the design document. The architecture diagram shows the trust boundaries.

- Python 3.11+ and Flask with Jinja templates: a small server-rendered application.

- SQLite through Python's `sqlite3`: one local database file and parameterized SQL.

- Planned `argon2-cffi`: master-password verification and separate key derivation.

- Planned `cryptography` AESGCM: authenticated encryption of complete vault entries.

- Planned Nginx and one Gunicorn worker on the same host: HTTPS and a simple in-memory session store. Restarting the worker will require users to log in again.

The browser submits the master password over HTTPS. The server checks its Argon2id hash and derives a separate encryption key with an independent salt. The key is kept only in the active server-side session. The cookie holds an opaque session identifier, never a key or password. The server can see unlocked credentials.

## Routes

| Method | Route | Purpose | Checkpoint 1 status |
| - | - | - | - |
| GET | `/` | Starting page | Implemented |
| GET | `/health` | Simple application status | Implemented |
| GET, POST | `/register` | Show form; create an account | Planned |
| GET, POST | `/login` | Show form; authenticate and unlock | Planned |
| POST | `/logout` | Invalidate the session and discard its key | Planned |
| GET | `/vault` | List the current user's entries | Planned |
| GET, POST | `/vault/new` | Show form; encrypt and create an entry | Planned |
| GET | `/vault/\<int:entry\_id\>` | View one owned entry | Planned |
| GET, POST | `/vault/\<int:entry\_id\>/edit` | Show form; update an owned entry | Planned |
| POST | `/vault/\<int:entry\_id\>/delete` | Delete an owned entry | Planned |


All vault routes will require a valid session. The server will check ownership for every operation. Every POST form, including login, registration and logout, will require a CSRF token. GET requests will not change vault data.

## Run locally

The current scaffold needs Python and internet access to install dependencies. It uses HTTP on loopback and has no credential forms. Before adding authentication, implement the HTTPS and session plan in the design.

Linux / macOS, including fish (activation is not required):

```
cd ICS0027-Web-Application-Security  
python3 -m venv .venv  
.venv/bin/python -m pip install -r requirements.txt  
.venv/bin/python -m flask --app app run --host 127.0.0.1 --port 5000
```

Windows PowerShell:

```
cd ICS0027-Web-Application-Security  
py -m venv .venv  
.\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt  
.\\.venv\\Scripts\\python.exe -m flask --app app run --host 127.0.0.1 --port 5000
```

Open [http://127.0.0.1:5000](http://127.0.0.1:5000/). The starting page should appear. Open [http://127.0.0.1:5000/health](http://127.0.0.1:5000/health) to see `\{"stage":"checkpoint-1-scaffold","status":"ok"\}`. Stop the server with Ctrl+C. No database initialization is needed at this stage. The development server must remain bound to loopback; do not enable debug mode or expose it publicly.

Validation: installed the pinned dependencies and verified the Flask CLI startup, page, health response, static CSS, response headers and Host restriction with Python 3.11+ on Linux. The Windows command sequence is provided for convenience.


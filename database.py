"""SQLite stores account metadata and encrypted entry payloads only."""

from pathlib import Path
import sqlite3

from crypto_utils import FORMAT, ITERATIONS, MEMORY, PARALLELISM, VERSION, encrypt_entry

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    login_username TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    kdf_salt BLOB NOT NULL CHECK(length(kdf_salt) = 16),
    kdf_memory INTEGER NOT NULL,
    kdf_iterations INTEGER NOT NULL,
    kdf_parallelism INTEGER NOT NULL,
    kdf_version INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS vault_entries (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES users(id),
    nonce BLOB NOT NULL CHECK(length(nonce) = 12),
    encrypted_data BLOB NOT NULL CHECK(length(encrypted_data) >= 16),
    format_version INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS entries_owner ON vault_entries(user_id);
"""


def connect(path):
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    return connection


def initialize(path):
    path = Path(path)
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    path.parent.chmod(0o700)
    path.touch(mode=0o600, exist_ok=True)
    path.chmod(0o600)
    connection = connect(path)
    try:
        connection.executescript(SCHEMA)
    finally:
        connection.close()


def create_user(connection, name, password_hash, salt):
    with connection:
        return connection.execute(
            "INSERT INTO users (login_username, password_hash, kdf_salt, kdf_memory, "
            "kdf_iterations, kdf_parallelism, kdf_version) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (name, password_hash, salt, MEMORY, ITERATIONS, PARALLELISM, VERSION)).lastrowid


def find_user(connection, name):
    return connection.execute("SELECT * FROM users WHERE login_username = ?", (name,)).fetchone()


def list_entries(connection, user_id):
    return connection.execute(
        "SELECT * FROM vault_entries WHERE user_id = ? ORDER BY id", (user_id,)).fetchall()


def find_entry(connection, user_id, entry_id):
    return connection.execute(
        "SELECT * FROM vault_entries WHERE id = ? AND user_id = ?",
        (entry_id, user_id)).fetchone()


def create_entry(connection, user_id, key, values):
    with connection:
        entry_id = connection.execute(
            "INSERT INTO vault_entries (user_id, nonce, encrypted_data, format_version) "
            "VALUES (?, zeroblob(12), zeroblob(16), ?)", (user_id, FORMAT)).lastrowid
        nonce, ciphertext = encrypt_entry(key, user_id, entry_id, values)
        connection.execute(
            "UPDATE vault_entries SET nonce = ?, encrypted_data = ? WHERE id = ? AND user_id = ?",
            (nonce, ciphertext, entry_id, user_id))
    return entry_id


def update_entry(connection, user_id, entry_id, key, values):
    nonce, ciphertext = encrypt_entry(key, user_id, entry_id, values)
    with connection:
        cursor = connection.execute(
            "UPDATE vault_entries SET nonce = ?, encrypted_data = ?, format_version = ? "
            "WHERE id = ? AND user_id = ?", (nonce, ciphertext, FORMAT, entry_id, user_id))
    return cursor.rowcount == 1


def delete_entry(connection, user_id, entry_id):
    with connection:
        cursor = connection.execute("DELETE FROM vault_entries WHERE id = ? AND user_id = ?",
                                    (entry_id, user_id))
    return cursor.rowcount == 1

"""Checkpoint 1 cryptographic scheme: independent Argon2id outputs and AES-GCM."""

import json
import secrets

from argon2 import PasswordHasher, extract_parameters
from argon2.exceptions import InvalidHashError, VerificationError
from argon2.low_level import Type, hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from validation import ValidationError, entry_fields

MEMORY = 65536
ITERATIONS = 3
PARALLELISM = 4
VERSION = 19
FORMAT = 1
HASHER = PasswordHasher(time_cost=ITERATIONS, memory_cost=MEMORY,
                        parallelism=PARALLELISM, hash_len=32, salt_len=16, type=Type.ID)


class VaultError(ValueError):
    pass


def hash_password(password):
    return HASHER.hash(password)


def verify_password(encoded, password):
    try:
        parameters = extract_parameters(encoded)
        expected = (Type.ID, VERSION, MEMORY, ITERATIONS, PARALLELISM, 32, 16)
        actual = (parameters.type, parameters.version, parameters.memory_cost,
                  parameters.time_cost, parameters.parallelism,
                  parameters.hash_len, parameters.salt_len)
        return actual == expected and HASHER.verify(encoded, password)
    except (InvalidHashError, VerificationError, TypeError, ValueError):
        return False


def derive_key(password, salt, memory=MEMORY, iterations=ITERATIONS,
               parallelism=PARALLELISM, version=VERSION):
    if (memory, iterations, parallelism, version) != (MEMORY, ITERATIONS, PARALLELISM, VERSION):
        raise VaultError("Unsupported KDF settings.")
    if not isinstance(salt, bytes) or len(salt) != 16:
        raise VaultError("Invalid KDF salt.")
    return hash_secret_raw(password.encode("utf-8"), salt, iterations, memory,
                           parallelism, 32, Type.ID, version)


def aad(user_id, entry_id, version):
    if (type(user_id) is not int or type(entry_id) is not int
            or user_id < 1 or entry_id < 1 or version != FORMAT):
        raise VaultError("Invalid record identifiers.")
    return f"{user_id}:{entry_id}:{version}".encode("utf-8")


def encrypt_entry(key, user_id, entry_id, values):
    entry_fields(values)
    plaintext = json.dumps(values, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, aad(user_id, entry_id, FORMAT))
    return nonce, ciphertext


def decrypt_entry(key, row):
    try:
        nonce, ciphertext = row["nonce"], row["encrypted_data"]
        if (not isinstance(nonce, bytes) or len(nonce) != 12
                or not isinstance(ciphertext, bytes) or not 16 <= len(ciphertext) <= 65536):
            raise ValueError
        plaintext = AESGCM(key).decrypt(
            nonce, ciphertext, aad(row["user_id"], row["id"], row["format_version"]))
        return entry_fields(json.loads(plaintext.decode("utf-8")))
    except (InvalidTag, ValueError, TypeError, KeyError, ValidationError):
        raise VaultError("Unable to open the encrypted entry.") from None

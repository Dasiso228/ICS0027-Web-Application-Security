"""Measure real KDF settings with a generated, non-user test passphrase."""
from importlib.metadata import version
import platform
import secrets
from statistics import mean
from time import perf_counter
from crypto_utils import derive_key, hash_password, verify_password


def main():
    password, salt = secrets.token_urlsafe(32), secrets.token_bytes(16)
    encoded = hash_password(password)
    verify_times, derive_times = [], []
    for _ in range(3):
        start = perf_counter()
        assert verify_password(encoded, password)
        verify_times.append(perf_counter() - start)
        start = perf_counter()
        key = derive_key(password, salt)
        derive_times.append(perf_counter() - start)
        del key
    print('Python:', platform.python_version())
    for package in ['Flask', 'argon2-cffi', 'cryptography']:
        print(f'{package}: {version(package)}')
    print(f'Argon2id verification mean (3 runs): {mean(verify_times):.4f} s')
    print(f'Argon2id key derivation mean (3 runs): {mean(derive_times):.4f} s')
    print(f'Combined mean: {mean(verify_times) + mean(derive_times):.4f} s')


if __name__ == '__main__':
    main()

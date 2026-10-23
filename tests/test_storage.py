import base64
from pathlib import Path
import secrets
import stat
import tempfile
import unittest
from unittest.mock import patch

import database
from crypto_utils import VaultError, decrypt_entry, derive_key, encrypt_entry, hash_password, verify_password
from validation import ValidationError, entry_fields, master_password

MASTER = 'Correct horse battery staple 42!'
ENTRY = {'title': 'PRIVATE_TITLE_MARKER', 'website_url': 'https://private.example.test',
         'username': 'PRIVATE_USERNAME_MARKER', 'password': 'PRIVATE_PASSWORD_MARKER',
         'notes': 'PRIVATE_NOTES_MARKER'}


class StorageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.salt = secrets.token_bytes(16)
        cls.key = derive_key(MASTER, cls.salt)
        cls.encoded = hash_password(MASTER)

    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.path = Path(self.folder.name) / 'private' / 'vault.sqlite3'
        database.initialize(self.path)
        self.db = database.connect(self.path)
        self.owner = database.create_user(self.db, 'alice', self.encoded, self.salt)
        self.other = database.create_user(self.db, 'bob', self.encoded, secrets.token_bytes(16))

    def tearDown(self):
        self.db.close()
        self.folder.cleanup()

    def test_independent_salts_hash_and_key(self):
        self.assertTrue(verify_password(self.encoded, MASTER))
        self.assertFalse(verify_password(self.encoded, 'A different master passphrase'))
        parts = self.encoded.split('$')
        auth_salt = base64.b64decode(parts[-2] + '==')
        auth_output = base64.b64decode(parts[-1] + '=')
        self.assertNotEqual(auth_salt, self.salt)
        self.assertNotEqual(auth_output, self.key)
        self.assertEqual(len(self.key), 32)
        self.assertNotEqual(self.key, derive_key(MASTER, secrets.token_bytes(16)))

    def test_database_contains_ciphertext_not_entry_fields(self):
        entry_id = database.create_entry(self.db, self.owner, self.key, ENTRY)
        row = database.find_entry(self.db, self.owner, entry_id)
        self.assertEqual(decrypt_entry(self.key, row), ENTRY)
        for value in [*ENTRY.values(), MASTER]:
            self.assertNotIn(value.encode(), self.path.read_bytes())
        self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
        self.assertEqual(stat.S_IMODE(self.path.parent.stat().st_mode), 0o700)

    def test_tampering_wrong_key_owner_id_and_version_fail(self):
        entry_id = database.create_entry(self.db, self.owner, self.key, ENTRY)
        original = dict(database.find_entry(self.db, self.owner, entry_id))
        changes = [dict(original, user_id=self.other), dict(original, id=entry_id + 1),
                   dict(original, format_version=2), dict(original, nonce=b'bad'),
                   dict(original, encrypted_data=original['encrypted_data'][:-1] + bytes([original['encrypted_data'][-1] ^ 1]))]
        for row in changes:
            with self.subTest(change=row.keys()), self.assertRaises(VaultError):
                decrypt_entry(self.key, row)
        with self.assertRaises(VaultError):
            decrypt_entry(secrets.token_bytes(32), original)

    def test_update_uses_fresh_nonce_and_checks_owner(self):
        entry_id = database.create_entry(self.db, self.owner, self.key, ENTRY)
        old = database.find_entry(self.db, self.owner, entry_id)
        changed = dict(ENTRY, password='UPDATED_PRIVATE_PASSWORD')
        self.assertFalse(database.update_entry(self.db, self.other, entry_id, self.key, changed))
        self.assertTrue(database.update_entry(self.db, self.owner, entry_id, self.key, changed))
        row = database.find_entry(self.db, self.owner, entry_id)
        self.assertNotEqual(old['nonce'], row['nonce'])
        self.assertEqual(decrypt_entry(self.key, row), changed)

    def test_encryption_failure_rolls_back_placeholder(self):
        with patch('database.encrypt_entry', side_effect=VaultError('test failure')):
            with self.assertRaises(VaultError):
                database.create_entry(self.db, self.owner, self.key, ENTRY)
        self.assertEqual(len(database.list_entries(self.db, self.owner)), 0)

    def test_read_delete_and_list_are_owner_scoped(self):
        entry_id = database.create_entry(self.db, self.owner, self.key, ENTRY)
        self.assertIsNone(database.find_entry(self.db, self.other, entry_id))
        self.assertEqual(database.list_entries(self.db, self.other), [])
        self.assertFalse(database.delete_entry(self.db, self.other, entry_id))
        self.assertTrue(database.delete_entry(self.db, self.owner, entry_id))

    def test_unsupported_kdf_settings_are_rejected(self):
        with self.assertRaises(VaultError):
            derive_key(MASTER, self.salt, memory=2**30)
        with self.assertRaises(VaultError):
            derive_key(MASTER, b'bad')

    def test_input_limits_and_password_spaces(self):
        spaced = '  A master passphrase with spaces  '
        self.assertEqual(master_password(spaced), spaced)
        for password in ['short', 'x' * 129]:
            with self.assertRaises(ValidationError):
                master_password(password)
        for url in ['javascript:alert(1)', 'file:///etc/passwd', 'https://', 'https://example.test:bad', 'https://exam\nple.test']:
            with self.subTest(url=url), self.assertRaises(ValidationError):
                entry_fields(dict(ENTRY, website_url=url))
        with self.assertRaises(ValidationError):
            entry_fields(dict(ENTRY, notes='x' * 2001))


if __name__ == '__main__':
    unittest.main()

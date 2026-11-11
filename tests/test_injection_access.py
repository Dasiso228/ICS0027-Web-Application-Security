"""Checkpoint 3: SQL injection payloads (OWASP A05:2025) and per-user access control (A01:2025).

Each test name starts with the test-case ID used in docs/SECURITY_TESTS.md.
"""
import ast
from pathlib import Path
import secrets

from markupsafe import escape

import database
from helpers import ENTRY, MASTER, AppTestCase

ROOT = Path(__file__).resolve().parents[1]

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR 1=1 --",
    "admin'--",
    '" OR ""="',
    "') OR ('1'='1",
    "'; DROP TABLE users; --",
    "1; DELETE FROM vault_entries --",
    "' UNION SELECT id, login_username, password_hash, kdf_salt, 1, 1, 1, 1 FROM users --",
    "' AND (SELECT COUNT(*) FROM users) > 0 --",
    "%' OR login_username LIKE '%",
]


class SqlInjectionTests(AppTestCase):
    def test_tc_sql_01_login_name_payloads_do_not_bypass_login(self):
        """TC-SQL-01: SQL injection payloads in the login name never authenticate."""
        self.register()
        self.logout()
        for payload in SQLI_PAYLOADS:
            with self.subTest(payload=payload):
                response = self.login(name=payload)
                self.assertEqual(response.status_code, 401)
                self.assertIn(b'Invalid username or master password.', response.data)
                self.assertFalse(self.signed_in())

    def test_tc_sql_02_password_payloads_do_not_bypass_login(self):
        """TC-SQL-02: SQL injection payloads in the master passphrase never authenticate."""
        self.register()
        self.logout()
        for payload in SQLI_PAYLOADS:
            with self.subTest(payload=payload):
                self.clock.now += 301  # stay under the login throttle so each payload reaches the check
                response = self.login(password=(payload + ' padding to 15+ chars')[:128])
                self.assertEqual(response.status_code, 401)
                self.assertFalse(self.signed_in())

    def test_tc_sql_03_registration_payloads_are_rejected_without_side_effects(self):
        """TC-SQL-03: SQL injection payloads as a new login name are rejected; tables stay intact."""
        for payload in SQLI_PAYLOADS:
            with self.subTest(payload=payload):
                response = self.post('/register', {'login_username': payload, 'master_password': MASTER,
                                     'confirm_password': MASTER}, self.csrf('/register'))
                self.assertEqual(response.status_code, 400)
        self.assertEqual(self.count_rows('users'), 0)
        self.assert_schema_intact()

    def test_tc_sql_04_entry_payloads_are_stored_as_literal_text(self):
        """TC-SQL-04: payloads saved in every entry field round-trip unchanged as plain data."""
        self.register()
        saved = [(self.add(dict(ENTRY, title=payload, username=payload, password=payload, notes=payload)), payload)
                 for payload in SQLI_PAYLOADS]
        for entry_id, payload in saved:
            with self.subTest(payload=payload):
                response = self.get(f'/vault/{entry_id}')
                self.assertEqual(response.status_code, 200)
                self.assertGreaterEqual(response.get_data(as_text=True).count(str(escape(payload))), 3)
        self.assertEqual(self.get('/vault').status_code, 200)
        self.assertEqual(self.count_rows('vault_entries'), len(SQLI_PAYLOADS))
        self.assertEqual(self.count_rows('users'), 1)
        self.assert_schema_intact()

    def test_tc_sql_05_route_parameter_payloads_never_reach_sql(self):
        """TC-SQL-05: injected entry IDs in the URL are rejected by the integer route converter."""
        self.register()
        entry_id = self.add()
        paths = [f'/vault/{entry_id}%20OR%201=1', f"/vault/{entry_id}'--", '/vault/0%20UNION%20SELECT%201',
                 f'/vault/{entry_id};DROP%20TABLE%20vault_entries', '/vault/-1',
                 f'/vault/{entry_id}%20OR%201=1/edit']
        for path in paths:
            with self.subTest(path=path):
                self.assertEqual(self.get(path).status_code, 404)
        token = self.csrf()
        response = self.post(f'/vault/{entry_id}%20OR%201=1/delete', {'confirm_delete': 'yes'}, token)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(self.count_rows('vault_entries'), 1)

    def test_tc_sql_06_data_layer_binds_payloads_as_parameters(self):
        """TC-SQL-06: called directly, without input validation, every query treats payloads as values."""
        owner = database.create_user(self.db, 'alice', 'not-a-real-hash', secrets.token_bytes(16))
        key = secrets.token_bytes(32)
        entry_id = database.create_entry(self.db, owner, key, ENTRY)
        for payload in SQLI_PAYLOADS:
            with self.subTest(payload=payload):
                self.assertIsNone(database.find_user(self.db, payload))
                self.assertIsNone(database.find_entry(self.db, owner, payload))
                self.assertIsNone(database.find_entry(self.db, payload, entry_id))
                self.assertEqual(database.list_entries(self.db, payload), [])
                self.assertFalse(database.delete_entry(self.db, payload, entry_id))
        evil_name = "x'); DROP TABLE users; --"
        evil_id = database.create_user(self.db, evil_name, 'not-a-real-hash', secrets.token_bytes(16))
        self.assertEqual(database.find_user(self.db, evil_name)['id'], evil_id)
        self.assertIsNotNone(database.find_entry(self.db, owner, entry_id))
        self.assert_schema_intact()

    def test_tc_sql_07_every_sql_statement_is_constant_and_parameterized(self):
        """TC-SQL-07: source audit - every execute() call uses a constant SQL string with ? placeholders."""
        sources = sorted(ROOT.glob('*.py')) + sorted((ROOT / 'tools').glob('*.py'))
        checked = 0
        for source in sources:
            tree = ast.parse(source.read_text(encoding='utf-8'), filename=str(source))
            constants = {target.id: node.value.value for node in tree.body
                         if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant)
                         and isinstance(node.value.value, str)
                         for target in node.targets if isinstance(target, ast.Name)}
            for node in ast.walk(tree):
                if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
                        and node.func.attr in {'execute', 'executemany', 'executescript'}):
                    continue
                with self.subTest(file=source.name, line=node.lineno):
                    argument = node.args[0]
                    if isinstance(argument, ast.Name):
                        self.assertIn(argument.id, constants, 'SQL must be a module-level string constant')
                        sql = constants[argument.id]
                    else:
                        self.assertIsInstance(argument, ast.Constant, 'SQL must be a string literal')
                        self.assertIsInstance(argument.value, str)
                        sql = argument.value
                    if any(word in sql.upper() for word in (' WHERE ', ' VALUES ', ' SET ')):
                        self.assertIn('?', sql)
                    checked += 1
        self.assertGreaterEqual(checked, 10)


class AccessControlTests(AppTestCase):
    def setUp(self):
        super().setUp()
        self.register('alice')
        self.alice_entry = self.add()
        self.bob = self.new_client()
        self.register('bob', self.bob)

    def test_tc_ac_01_other_user_cannot_read_entry(self):
        """TC-AC-01: Bob requests Alice's entry by ID and gets the same 404 as for a missing ID."""
        with self.assertLogs(self.app.logger, 'INFO') as logs:
            foreign = self.get(f'/vault/{self.alice_entry}', self.bob)
            missing = self.get('/vault/999999', self.bob)
        for response in (foreign, missing):
            self.assertEqual(response.status_code, 404)
            self.assertIn(b'Not found.', response.data)
            for value in ENTRY.values():
                self.assertNotIn(value.encode(), response.data)
        self.assertTrue(any('entry_access' in line and 'denied' in line for line in logs.output))
        self.assertIn(ENTRY['password'].encode(), self.get(f'/vault/{self.alice_entry}').data)

    def test_tc_ac_02_other_user_cannot_edit_or_delete_entry(self):
        """TC-AC-02: Bob cannot open the edit form, submit an edit or delete Alice's entry."""
        token = self.csrf('/vault', self.bob)
        changed = dict(ENTRY, password='BOB_WAS_HERE_123')
        self.assertEqual(self.get(f'/vault/{self.alice_entry}/edit', self.bob).status_code, 404)
        self.assertEqual(self.post(f'/vault/{self.alice_entry}/edit', changed, token, self.bob).status_code, 404)
        self.assertEqual(self.post(f'/vault/{self.alice_entry}/delete', {'confirm_delete': 'yes'},
                                   token, self.bob).status_code, 404)
        page = self.get(f'/vault/{self.alice_entry}').data
        self.assertIn(ENTRY['password'].encode(), page)
        self.assertNotIn(b'BOB_WAS_HERE_123', page)

    def test_tc_ac_03_vault_list_contains_only_own_entries(self):
        """TC-AC-03: each vault list shows only the signed-in user's entries."""
        self.add(dict(ENTRY, title='Bob bank', password='BOB_SECRET_PASSWORD_456'), self.bob)
        alice_list, bob_list = self.get('/vault').data, self.get('/vault', self.bob).data
        self.assertIn(b'Alice private mail', alice_list)
        self.assertNotIn(b'Bob bank', alice_list)
        self.assertIn(b'Bob bank', bob_list)
        self.assertNotIn(b'Alice private mail', bob_list)

    def test_tc_ac_04_forged_owner_fields_are_ignored(self):
        """TC-AC-04: user_id/owner_id fields injected into forms cannot assign or move entries."""
        token = self.csrf('/vault', self.bob)
        response = self.post('/vault/new', dict(ENTRY, user_id='1', owner_id='1'), token, self.bob)
        self.assertEqual(response.status_code, 303)
        bob_entry = int(response.headers['Location'].rsplit('/', 1)[-1])
        self.assertEqual(self.owner_of(bob_entry), 2)
        response = self.post(f'/vault/{bob_entry}/edit', dict(ENTRY, user_id='1'), token, self.bob)
        self.assertEqual(response.status_code, 303)
        self.assertEqual(self.owner_of(bob_entry), 2)
        self.assertEqual(self.owner_of(self.alice_entry), 1)

    def test_tc_ac_05_every_vault_route_requires_authentication(self):
        """TC-AC-05: every vault route sends anonymous visitors to login and changes nothing."""
        anonymous = self.new_client()
        rules = [rule for rule in self.app.url_map.iter_rules()
                 if rule.endpoint.startswith('vault.') or rule.endpoint == 'auth.logout']
        self.assertEqual(len(rules), 6)
        for rule in rules:
            path = rule.rule.replace('<int:entry_id>', str(self.alice_entry))
            with self.subTest(rule=rule.rule):
                if 'GET' in rule.methods:
                    response = self.get(path, anonymous)
                    self.assertEqual(response.status_code, 303)
                    self.assertTrue(response.headers['Location'].endswith('/login'))
                if 'POST' in rule.methods:
                    self.assertEqual(self.post(path, {'confirm_delete': 'yes'}, client=anonymous).status_code, 400)
                    token = self.csrf('/login', anonymous)
                    response = self.post(path, dict(ENTRY, confirm_delete='yes'), token, anonymous)
                    self.assertEqual(response.status_code, 303)
                    self.assertTrue(response.headers['Location'].endswith('/login'))
        self.assertEqual(self.count_rows('vault_entries'), 1)
        self.assertIn(ENTRY['password'].encode(), self.get(f'/vault/{self.alice_entry}').data)

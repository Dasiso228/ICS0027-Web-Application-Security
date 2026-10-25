from html.parser import HTMLParser
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch
from werkzeug.datastructures import MultiDict
from werkzeug.exceptions import ServiceUnavailable

from app import create_app
import database
from security import COOKIE, LoginThrottle, SessionStore

MASTER = 'Correct horse battery staple 42!'
ENTRY = {'title': 'Private mail', 'website_url': 'https://mail.example.test',
         'username': 'private-user', 'password': 'PRIVATE_TEST_PASSWORD_123', 'notes': 'Private note'}
BASE = 'https://localhost'


class Clock:
    def __init__(self):
        self.now = 100.0
    def __call__(self):
        return self.now


class Tags(HTMLParser):
    def __init__(self, text):
        super().__init__()
        self.tags = []
        self.feed(text)
    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class WebTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.clock = Clock()
        self.config = {'TESTING': True, 'DATABASE': str(Path(self.folder.name) / 'data' / 'vault.sqlite3'),
                       'CLOCK': self.clock, 'SESSION_SWEEP': False}
        self.app = create_app(self.config)
        self.client = self.app.test_client()
        self.db = database.connect(self.config['DATABASE'])

    def tearDown(self):
        self.app.extensions['sessions'].close()
        self.db.close()
        self.folder.cleanup()

    def get(self, path, client=None, **kwargs):
        return (client or self.client).get(path, base_url=BASE, **kwargs)

    def csrf(self, path='/vault', client=None):
        response = self.get(path, client)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return re.search(r'name="csrf_token" value="([A-Za-z0-9_-]{43})"', response.get_data(as_text=True)).group(1)

    def post(self, path, data, csrf=None, client=None, **kwargs):
        if csrf is not None:
            data = dict(data, csrf_token=csrf)
        return (client or self.client).post(path, data=data, base_url=BASE, **kwargs)

    def register(self, name='alice', client=None):
        csrf = self.csrf('/register', client)
        response = self.post('/register', {'login_username': name, 'master_password': MASTER,
                             'confirm_password': MASTER}, csrf, client)
        self.assertEqual(response.status_code, 303, response.get_data(as_text=True))
        return response

    def add(self, values=None):
        response = self.post('/vault/new', values or ENTRY, self.csrf('/vault/new'))
        self.assertEqual(response.status_code, 303)
        return int(response.headers['Location'].rsplit('/', 1)[-1])

    def login(self, password=MASTER, name='alice', client=None):
        return self.post('/login', {'login_username': name, 'master_password': password},
                         self.csrf('/login', client), client)

    def test_register_login_crud_logout_and_restart(self):
        self.register()
        entry_id = self.add()
        self.assertNotIn(ENTRY['password'].encode(), self.get('/vault').data)
        self.assertIn(ENTRY['password'].encode(), self.get(f'/vault/{entry_id}').data)
        changed = dict(ENTRY, password='UPDATED_PRIVATE_PASSWORD_456')
        response = self.post(f'/vault/{entry_id}/edit', changed, self.csrf(f'/vault/{entry_id}/edit'))
        self.assertEqual(response.status_code, 303)
        self.assertIn(changed['password'].encode(), self.get(f'/vault/{entry_id}').data)
        old_token = self.client.get_cookie(COOKIE).value
        self.app.extensions['sessions'].close()
        self.app = create_app(self.config)
        self.client = self.app.test_client()
        self.client.set_cookie(COOKIE, old_token)
        self.assertEqual(self.get('/vault').status_code, 303)
        self.assertEqual(self.login().status_code, 303)
        self.assertIn(changed['password'].encode(), self.get(f'/vault/{entry_id}').data)
        self.assertEqual(self.post(f'/vault/{entry_id}/delete', {'confirm_delete': 'yes'}, self.csrf()).status_code, 303)
        self.assertEqual(self.get(f'/vault/{entry_id}').status_code, 404)
        self.assertEqual(self.post('/logout', {}, self.csrf()).status_code, 303)
        self.assertIsNone(self.client.get_cookie(COOKIE))

    def test_cookie_flags_rotation_fixation_and_logout_replay(self):
        old_csrf = self.csrf('/register')
        old_token = self.client.get_cookie(COOKIE).value
        response = self.post('/register', {'login_username': 'alice', 'master_password': MASTER,
                             'confirm_password': MASTER}, old_csrf)
        cookie = response.headers['Set-Cookie']
        for flag in ['Secure', 'HttpOnly', 'SameSite=Strict', 'Path=/', 'Max-Age=3600']:
            self.assertIn(flag, cookie)
        self.assertNotIn('Domain=', cookie)
        token = self.client.get_cookie(COOKIE).value
        self.assertNotEqual(old_token, token)
        self.assertEqual(len(token), 43)
        self.assertNotIn(MASTER, cookie)
        self.assertNotEqual(old_csrf, self.csrf())
        attacker = self.app.test_client()
        attacker.set_cookie(COOKIE, old_token)
        self.assertEqual(self.get('/vault', attacker).status_code, 303)
        self.post('/logout', {}, self.csrf())
        attacker.set_cookie(COOKIE, token)
        self.assertEqual(self.get('/vault', attacker).status_code, 303)
        anonymous_csrf = self.csrf('/login')
        anonymous_token = self.client.get_cookie(COOKIE).value
        self.assertEqual(self.post('/login', {'login_username': 'alice', 'master_password': MASTER}, anonymous_csrf).status_code, 303)
        self.assertNotEqual(anonymous_token, self.client.get_cookie(COOKIE).value)
        attacker.set_cookie(COOKIE, anonymous_token)
        self.assertEqual(self.get('/vault', attacker).status_code, 303)

    def test_missing_wrong_and_cross_session_csrf_rejected(self):
        for path in ['/register', '/login', '/logout', '/vault/new', '/vault/1/edit', '/vault/1/delete']:
            self.assertEqual(self.post(path, {}).status_code, 400)
        self.register()
        other = self.app.test_client()
        foreign_token = self.csrf('/login', other)
        self.assertEqual(self.post('/vault/new', ENTRY, foreign_token).status_code, 400)
        self.assertEqual(self.post('/vault/new', ENTRY, 'é' * 43).status_code, 400)
        self.assertEqual(database.list_entries(self.db, 1), [])

    def test_second_account_cannot_read_edit_delete_or_forge_owner(self):
        self.register()
        entry_id = self.add()
        bob = self.app.test_client()
        self.register('bob', bob)
        self.assertNotIn(ENTRY['title'].encode(), self.get('/vault', bob).data)
        for suffix in ['', '/edit']:
            self.assertEqual(self.get(f'/vault/{entry_id}{suffix}', bob).status_code, 404)
        csrf = self.csrf('/vault', bob)
        self.assertEqual(self.post(f'/vault/{entry_id}/edit', ENTRY, csrf, bob).status_code, 404)
        self.assertEqual(self.post(f'/vault/{entry_id}/delete', {'confirm_delete': 'yes'}, csrf, bob).status_code, 404)
        response = self.post('/vault/new', dict(ENTRY, user_id='1'), csrf, bob)
        self.assertEqual(response.status_code, 303)
        bob_id = int(response.headers['Location'].rsplit('/', 1)[-1])
        self.assertIsNone(database.find_entry(self.db, 1, bob_id))
        self.assertIsNotNone(database.find_entry(self.db, 2, bob_id))

    def test_xss_escaped_on_list_show_and_edit(self):
        self.register()
        values = dict(ENTRY, title='<script>alert(1)</script>',
                      username='" autofocus onfocus="alert(1)', notes='</textarea><img src=x onerror=alert(1)>')
        entry_id = self.add(values)
        for path in ['/vault', f'/vault/{entry_id}', f'/vault/{entry_id}/edit']:
            response = self.get(path)
            self.assertEqual(response.status_code, 200)
            parsed = Tags(response.get_data(as_text=True))
            self.assertFalse(any(tag in ('script', 'img') for tag, _ in parsed.tags))
            self.assertFalse(any('onfocus' in attrs or 'autofocus' in attrs for _, attrs in parsed.tags))
            self.assertIn(b'&lt;script&gt;', response.data)

    def test_sql_payload_is_plain_data_and_auth_is_not_bypassed(self):
        self.register()
        values = dict(ENTRY, title="x'); DROP TABLE users; --", username="' OR 1=1 --")
        entry_id = self.add(values)
        self.assertEqual(self.get(f'/vault/{entry_id}').status_code, 200)
        self.assertIsNotNone(database.find_user(self.db, 'alice'))
        other = self.app.test_client()
        self.assertEqual(self.login(name="' OR 1=1 --", client=other).status_code, 401)
        self.assertEqual(self.get('/vault', other).status_code, 303)

    def test_tampered_database_is_rejected_without_plaintext(self):
        self.register()
        entry_id = self.add()
        with self.db:
            self.db.execute('UPDATE vault_entries SET encrypted_data = ? WHERE id = ?', (b'X' * 80, entry_id))
        response = self.get(f'/vault/{entry_id}')
        self.assertEqual(response.status_code, 400)
        self.assertNotIn(ENTRY['password'].encode(), response.data)
        self.assertEqual(self.get('/vault').status_code, 400)

    def test_wrong_password_generic_error_and_no_key_derivation(self):
        self.register()
        self.post('/logout', {}, self.csrf())
        with patch('auth_routes.derive_key') as derive:
            first = self.login(password='Wrong master passphrase 123')
            second = self.login(name='unknown')
            derive.assert_not_called()
        self.assertEqual(first.status_code, 401)
        self.assertEqual(second.status_code, 401)
        self.assertEqual(first.data, second.data)
        self.assertEqual(self.get('/vault').status_code, 303)

    def test_throttle_blocks_sixth_failure_and_expires(self):
        for attempt in range(5):
            self.assertEqual(self.login(name='unknown').status_code, 401)
        self.assertEqual(self.login(name='another').status_code, 429)
        self.clock.now += 301
        self.assertEqual(self.login(name='unknown').status_code, 401)

    def test_request_field_url_and_duplicate_limits(self):
        self.register()
        for values in [dict(ENTRY, title='x' * 101), dict(ENTRY, password='x' * 1025),
                       dict(ENTRY, website_url='javascript:alert(1)')]:
            self.assertEqual(self.post('/vault/new', values, self.csrf()).status_code, 400)
        token = self.csrf()
        data = MultiDict([*ENTRY.items(), ('csrf_token', token), ('csrf_token', token)])
        self.assertEqual(self.post('/vault/new', data).status_code, 400)
        response = self.client.post('/vault/new', data=b'x' * 65537,
                                    content_type='application/x-www-form-urlencoded', base_url=BASE)
        self.assertEqual(response.status_code, 413)
        self.assertEqual(database.list_entries(self.db, 1), [])

    def test_https_host_headers_and_safe_methods(self):
        self.assertEqual(self.client.get('/health').status_code, 400)
        self.assertEqual(self.client.get('/health', base_url='https://evil.test').status_code, 400)
        response = self.get('/health')
        self.assertEqual(response.status_code, 200)
        for name, value in [('Cache-Control', 'no-store'), ('Referrer-Policy', 'no-referrer'),
                            ('X-Content-Type-Options', 'nosniff'), ('X-Frame-Options', 'DENY')]:
            self.assertEqual(response.headers[name], value)
        self.assertIn("frame-ancestors 'none'", response.headers['Content-Security-Policy'])
        self.assertIn('max-age=', response.headers['Strict-Transport-Security'])
        self.register()
        entry_id = self.add()
        self.assertEqual(self.get('/logout').status_code, 405)
        self.assertEqual(self.get(f'/vault/{entry_id}/delete').status_code, 405)
        self.assertEqual(self.get(f'/vault/{entry_id}').status_code, 200)
        self.assertEqual(self.post(f'/vault/{entry_id}/delete', {'confirm_delete': 'no'}, self.csrf()).status_code, 400)

    def test_idle_and_absolute_expiry_enforced(self):
        self.register()
        self.clock.now += 900
        self.assertEqual(self.get('/vault').status_code, 303)
        self.assertEqual(self.login().status_code, 303)
        for _ in range(5):
            self.clock.now += 600
            self.assertEqual(self.get('/vault').status_code, 200)
        self.clock.now += 600
        self.assertEqual(self.get('/vault').status_code, 303)

    def test_kdf_concurrency_limit_fails_closed(self):
        token = self.csrf('/register')
        semaphore = self.app.extensions['kdf_slots']
        semaphore.acquire()
        semaphore.acquire()
        try:
            response = self.post('/register', {'login_username': 'alice', 'master_password': MASTER,
                                 'confirm_password': MASTER}, token)
            self.assertEqual(response.status_code, 503)
            self.assertIsNone(database.find_user(self.db, 'alice'))
        finally:
            semaphore.release()
            semaphore.release()

    def test_logs_exclude_passwords_cookie_and_vault_data(self):
        with self.assertLogs(self.app.logger, level='INFO') as captured:
            self.register()
            token = self.client.get_cookie(COOKIE).value
            self.add()
            self.post('/logout', {}, self.csrf())
            self.login(password='Wrong master passphrase 123')
        output = '\n'.join(captured.output)
        for secret in [MASTER, token, ENTRY['password'], ENTRY['title'], 'Wrong master passphrase 123']:
            self.assertNotIn(secret, output)


class SessionTests(unittest.TestCase):
    def test_anonymous_expiry_capacity_and_purge(self):
        clock = Clock()
        store = SessionStore(clock, capacity=2, sweep=False)
        anonymous = store.create()
        authenticated = store.create(1, b'x' * 32)
        with self.assertRaises(ServiceUnavailable):
            store.create()
        clock.now += 901
        store.purge()
        self.assertEqual(store.records, {})
        self.assertIsNone(store.get(anonymous.token))
        self.assertIsNone(store.get(authenticated.token))

    def test_throttle_covers_account_and_ip_separately(self):
        clock = Clock()
        throttle = LoginThrottle(clock)
        for i in range(5):
            throttle.failed('alice', f'192.0.2.{i}')
        self.assertFalse(throttle.allowed('alice', '198.51.100.1'))
        self.assertTrue(throttle.allowed('bob', '198.51.100.1'))
        for i in range(5):
            throttle.failed(f'user{i}', '203.0.113.1')
        self.assertFalse(throttle.allowed('fresh', '203.0.113.1'))
        clock.now += 301
        self.assertTrue(throttle.allowed('alice', '203.0.113.1'))


if __name__ == '__main__':
    unittest.main()

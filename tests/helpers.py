"""Shared fixture for the Checkpoint 3 security tests"""
from html.parser import HTMLParser
from pathlib import Path
import re
import tempfile
import unittest

from app import create_app
import database

MASTER = 'Correct horse battery staple 42!'
ENTRY = {'title': 'Alice private mail', 'website_url': 'https://mail.example.test',
         'username': 'alice-mail', 'password': 'ALICE_SECRET_PASSWORD_123', 'notes': 'Alice private note'}
BASE = 'https://localhost'
CSRF_PATTERN = re.compile(r'name="csrf_token" value="([A-Za-z0-9_-]{43})"')
COUNT_QUERIES = {'users': 'SELECT COUNT(*) FROM users',
                 'vault_entries': 'SELECT COUNT(*) FROM vault_entries'}


class Clock:
    def __init__(self):
        self.now = 100.0

    def __call__(self):
        return self.now


class Tags(HTMLParser):
    """Collects the start tags and attributes a browser would really create"""

    def __init__(self, text):
        super().__init__()
        self.tags = []
        self.feed(text)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))


class AppTestCase(unittest.TestCase):
    """Temporary database, fake clock and browser-like request helpers"""

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

    def new_client(self):
        return self.app.test_client()

    def get(self, path, client=None, **kwargs):
        return (client or self.client).get(path, base_url=BASE, **kwargs)

    def post(self, path, data, csrf=None, client=None, **kwargs):
        if csrf is not None:
            data = dict(data, csrf_token=csrf)
        return (client or self.client).post(path, data=data, base_url=BASE, **kwargs)

    def csrf(self, path='/vault', client=None):
        response = self.get(path, client)
        self.assertEqual(response.status_code, 200, response.get_data(as_text=True))
        return CSRF_PATTERN.search(response.get_data(as_text=True)).group(1)

    def register(self, name='alice', client=None):
        response = self.post('/register', {'login_username': name, 'master_password': MASTER,
                             'confirm_password': MASTER}, self.csrf('/register', client), client)
        self.assertEqual(response.status_code, 303, response.get_data(as_text=True))
        return response

    def login(self, name='alice', password=MASTER, client=None):
        return self.post('/login', {'login_username': name, 'master_password': password},
                         self.csrf('/login', client), client)

    def logout(self, client=None):
        return self.post('/logout', {}, self.csrf('/vault', client), client)

    def add(self, values=None, client=None):
        response = self.post('/vault/new', values or ENTRY, self.csrf('/vault/new', client), client)
        self.assertEqual(response.status_code, 303, response.get_data(as_text=True))
        return int(response.headers['Location'].rsplit('/', 1)[-1])

    def signed_in(self, client=None):
        return self.get('/vault', client).status_code == 200

    def count_rows(self, table):
        return self.db.execute(COUNT_QUERIES[table]).fetchone()[0]

    def owner_of(self, entry_id):
        return self.db.execute('SELECT user_id FROM vault_entries WHERE id = ?', (entry_id,)).fetchone()[0]

    def assert_schema_intact(self):
        tables = {row[0] for row in self.db.execute("SELECT name FROM sqlite_master WHERE type = 'table'")}
        self.assertLessEqual({'users', 'vault_entries'}, tables)

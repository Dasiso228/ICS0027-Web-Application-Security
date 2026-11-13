"""Checkpoint 3: secure error handling (OWASP A10:2025) and structured logging (A09:2025).

Each test name starts with the test-case ID used in docs/SECURITY_TESTS.md.
"""
import base64
import json
import logging
import os
from pathlib import Path
import re
import sqlite3
import stat
from unittest.mock import patch
from urllib.parse import quote

from audit_log import JsonLinesFileHandler
from helpers import BASE, ENTRY, MASTER, AppTestCase
from security import COOKIE

REQUIRED_FIELDS = {'ts', 'level', 'event', 'outcome', 'user_id', 'request_id', 'session_ref', 'ip', 'method', 'path'}
REFERENCE = re.compile(r"Reference:\s*([0-9a-f]{16})")
WRONG_PASSWORD = 'Wrong master passphrase 123'


def records(captured):
    """Every captured log message must be exactly one JSON object."""
    return [json.loads(record.getMessage()) for record in captured.records]


class ErrorHandlingTests(AppTestCase):
    def test_tc_err_01_unhandled_exception_shows_generic_page_only(self):
        """TC-ERR-01: an unexpected exception gives a generic 500 page; details stay in the server log."""
        self.register()
        secret = 'SECRET_INTERNAL_DETAIL /srv/app/instance/vault.sqlite3'
        with patch('vault_routes.database.list_entries', side_effect=RuntimeError(secret)), \
                self.assertLogs(self.app.logger, 'INFO') as captured:
            response = self.get('/vault')
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 500)
        self.assertIn('An internal error occurred.', body)
        for leak in [secret, 'Traceback', 'RuntimeError', 'vault_routes', 'File "']:
            self.assertNotIn(leak, body)
        event = next(item for item in records(captured) if item['event'] == 'server_error')
        self.assertEqual(event['request_id'], REFERENCE.search(body).group(1))
        self.assertEqual((event['level'], event['error_type'], event['status']), ('ERROR', 'RuntimeError', 500))
        self.assertTrue(event['location'])
        self.assertNotIn('SECRET_INTERNAL_DETAIL', '\n'.join(captured.output))

    def test_tc_err_02_database_errors_are_not_disclosed(self):
        """TC-ERR-02: a database failure whose message contains SQL is reported generically."""
        self.register()
        entry_id = self.add()
        error = sqlite3.OperationalError('database is locked: SELECT * FROM vault_entries WHERE id = 1')
        with patch('vault_routes.database.find_entry', side_effect=error):
            response = self.get(f'/vault/{entry_id}')
        body = response.get_data(as_text=True)
        self.assertEqual(response.status_code, 500)
        for leak in ['SELECT', 'vault_entries', 'OperationalError', 'sqlite', 'locked']:
            self.assertNotIn(leak, body)

    def test_tc_err_03_http_errors_use_fixed_messages_and_reference(self):
        """TC-ERR-03: 400, 404, 405 and 413 errors use fixed text plus a reference ID, never request data."""
        self.register()
        responses = {
            400: self.post('/vault/new', ENTRY),
            404: self.get('/no-such-page/probe?q=probe'),
            405: self.get('/logout'),
            413: self.client.post('/vault/new', data=b'x' * 65537, base_url=BASE,
                                  content_type='application/x-www-form-urlencoded'),
        }
        messages = {400: 'Unable to process this request.', 404: 'Not found.',
                    405: 'Method not allowed.', 413: 'Request too large.'}
        for code, response in responses.items():
            with self.subTest(status=code):
                body = response.get_data(as_text=True)
                self.assertEqual(response.status_code, code)
                self.assertIn(messages[code], body)
                self.assertRegex(body, REFERENCE)
                self.assertNotIn('probe', body)

    def test_tc_err_04_debug_is_off_and_transport_errors_are_generic(self):
        """TC-ERR-04: debug mode is off; plain HTTP and foreign Host headers (GET and POST) get short generic errors."""
        self.assertFalse(self.app.debug)
        plain_http = self.client.get('/health')
        self.assertEqual(plain_http.status_code, 400)
        self.assertIn(b'Unable to process this request.', plain_http.data)
        for send in (self.client.get, self.client.post):
            with self.subTest(method=send.__name__):
                response = send('/login', base_url='https://evil.test')
                self.assertEqual((response.status_code, response.data), (400, b'Invalid Host header.'))


class StructuredLoggingTests(AppTestCase):
    def scenario(self):
        """A normal session mixed with attacks; returns the captured log, entry ID and every secret used."""
        with self.assertLogs(self.app.logger, 'INFO') as captured:
            self.register('alice')
            cookie = self.client.get_cookie(COOKIE).value
            csrf = self.csrf()
            key = self.app.extensions['sessions'].get(cookie).key
            entry_id = self.add()
            self.post(f'/vault/{entry_id}/edit', dict(ENTRY, password='EDITED_SECRET_789'),
                      self.csrf(f'/vault/{entry_id}/edit'))
            self.post('/vault/new', dict(ENTRY, website_url='javascript:alert(1)'), self.csrf())
            bob = self.new_client()
            self.register('bob', bob)
            self.get(f'/vault/{entry_id}', bob)
            self.post('/vault/new', ENTRY, client=bob)
            self.post(f'/vault/{entry_id}/delete', {'confirm_delete': 'yes'}, self.csrf())
            self.logout()
            self.login(password=WRONG_PASSWORD)
            self.login(name="' OR 1=1 --")
        secrets = [MASTER, WRONG_PASSWORD, cookie, csrf, key.hex(), base64.b64encode(key).decode(),
                   *ENTRY.values(), 'EDITED_SECRET_789', 'javascript:alert(1)']
        return captured, entry_id, secrets

    def test_tc_log_01_security_events_are_structured_json(self):
        """TC-LOG-01: each event is one JSON object with time, user, source address, request and outcome."""
        captured, entry_id, _ = self.scenario()
        events = records(captured)
        for event in events:
            self.assertLessEqual(REQUIRED_FIELDS, set(event))
            self.assertRegex(event['ts'], r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$')
            self.assertRegex(event['request_id'], r'^[0-9a-f]{16}$')
            self.assertEqual(event['ip'], '127.0.0.1')
            self.assertEqual(event['level'], 'INFO' if event['outcome'] == 'success' else 'WARNING')
        seen = {(e['event'], e['outcome'], e['user_id'], e.get('entry_id'), e.get('status'), e.get('reason'))
                for e in events}
        expected = {
            ('registration', 'success', 1, None, None, None),
            ('entry_create', 'success', 1, entry_id, None, None),
            ('entry_update', 'success', 1, entry_id, None, None),
            ('entry_validation', 'rejected', 1, None, None, None),
            ('registration', 'success', 2, None, None, None),
            ('entry_access', 'denied', 2, entry_id, None, None),
            ('http_error', 'rejected', 2, None, 404, None),
            ('csrf', 'denied', 2, None, None, None),
            ('http_error', 'rejected', 2, None, 400, None),
            ('entry_delete', 'success', 1, entry_id, None, None),
            ('logout', 'success', 1, None, None, None),
            ('login', 'failure', 1, None, None, 'invalid_credentials'),
            ('login', 'failure', None, None, None, 'invalid_input'),
        }
        self.assertLessEqual(expected, seen)

    def test_tc_log_02_logs_never_contain_secrets(self):
        """TC-LOG-02: passwords, cookie and CSRF tokens, the vault key and entry contents never reach the log."""
        captured, _, secrets = self.scenario()
        output = '\n'.join(captured.output)
        for secret in secrets:
            with self.subTest(secret=secret[:12]):
                self.assertNotIn(secret, output)

    def test_tc_log_03_log_injection_cannot_forge_records(self):
        """TC-LOG-03: CR/LF in request data or in any log message cannot forge a record or add a traceback."""
        forged = '\r\n{"event":"login","outcome":"success","user_id":1}\r\n'
        self.get('/vault/' + quote(forged))
        self.client.post('/login' + quote(forged), data={}, base_url='https://evil.test')
        try:
            raise RuntimeError('SECRET_INTERNAL_DETAIL')
        except RuntimeError:
            self.app.logger.exception('Exception on /login' + forged)
        lines = Path(self.app.config['LOG_FILE']).read_text(encoding='utf-8').splitlines()
        events = [json.loads(line) for line in lines]
        self.assertEqual([event['event'] for event in events], ['http_error', 'http_error', 'app_log'])
        self.assertEqual(sum(event.get('path', '').endswith(forged) for event in events), 2)
        self.assertEqual(events[-1]['error_type'], 'RuntimeError')
        for leak in ('Traceback', 'SECRET_INTERNAL_DETAIL', 'File "'):
            self.assertNotIn(leak, '\n'.join(lines))

    def test_tc_log_04_log_file_is_private_json_lines_and_bounded(self):
        """TC-LOG-04: events are appended as JSON lines to a private file that rotates at its size limit."""
        log_file = Path(self.config['DATABASE']).with_name('security.log')
        self.assertEqual(self.app.config['LOG_FILE'], str(log_file))
        self.register()
        self.get('/missing')
        events = [json.loads(line) for line in log_file.read_text(encoding='utf-8').splitlines()]
        self.assertLessEqual({'registration', 'http_error'}, {event['event'] for event in events})
        if os.name == 'posix':
            self.assertEqual(stat.S_IMODE(log_file.stat().st_mode), 0o600)
        small = Path(self.folder.name) / 'small.log'
        handler = JsonLinesFileHandler(small, max_bytes=300)
        handler.setFormatter(logging.Formatter('%(message)s'))
        for number in range(10):
            handler.handle(logging.makeLogRecord({'msg': json.dumps({'n': number, 'pad': 'x' * 60})}))
        self.assertLessEqual(small.stat().st_size, 300)
        self.assertTrue(small.with_name('small.log.1').exists())

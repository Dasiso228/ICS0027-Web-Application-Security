"""Checkpoint 3: XSS defences (OWASP A05:2025) - output encoding, input validation and CSP.

Each test name starts with the test-case ID used in docs/SECURITY_TESTS.md.
"""
from pathlib import Path
import re

from jinja2 import DictLoader
from markupsafe import escape

from helpers import ENTRY, MASTER, AppTestCase, Tags

ROOT = Path(__file__).resolve().parents[1]

XSS_PAYLOADS = [
    "<script>alert('xss')</script>",
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '<svg/onload=alert(1)>',
    '</textarea><script>alert(1)</script>',
    '" autofocus onfocus="alert(1)',
    '<iframe src="javascript:alert(1)"></iframe>',
    '<a href="javascript:alert(1)">click me</a>',
    '<body onload=alert(1)>',
    '<<SCRIPT>alert(1)//<</SCRIPT>',
    "{{ config}}{{ 'ssti' * 3}}",
]
TEMPLATE_TAGS = {'html', 'head', 'meta', 'title', 'link', 'body', 'main', 'nav', 'a', 'form', 'input',
                 'button', 'p', 'h1', 'ul', 'li', 'span', 'dl', 'dt', 'dd', 'details', 'summary', 'pre',
                 'label', 'textarea'}
URL_ATTRIBUTES = {'href', 'src', 'action', 'formaction'}


class XssTests(AppTestCase):
    def assert_no_injected_markup(self, page):
        tags = Tags(page).tags
        for tag, attrs in tags:
            self.assertIn(tag, TEMPLATE_TAGS, f'unexpected <{tag}> element')
            for name, value in attrs.items():
                self.assertFalse(name.startswith('on'), f'<{tag}> has event handler{name}')
                self.assertNotIn(name, {'autofocus', 'style'})
                if name in URL_ATTRIBUTES and value:
                    self.assertFalse(value.strip().lower().startswith('javascript:'))
        self.assertEqual([tag for tag, _ in tags].count('body'), 1)
        self.assertNotIn('sstisstissti', page)

    def test_tc_xss_01_stored_payloads_are_escaped_on_every_page(self):
        """TC-XSS-01: stored payloads in every text field render as inert text on list, view and edit pages."""
        self.register()
        ids = [self.add(dict(ENTRY, title=payload, username=payload, password=payload, notes=payload))
               for payload in XSS_PAYLOADS]
        paths = ['/vault'] + [f'/vault/{i}' for i in ids] + [f'/vault/{i}/edit' for i in ids]
        for path in paths:
            with self.subTest(path=path):
                response = self.get(path)
                self.assertEqual(response.status_code, 200)
                self.assert_no_injected_markup(response.get_data(as_text=True))
        for entry_id, payload in zip(ids, XSS_PAYLOADS):
            with self.subTest(payload=payload):
                self.assertIn(str(escape(payload)), self.get(f'/vault/{entry_id}').get_data(as_text=True))

    def test_tc_xss_02_dangerous_url_schemes_rejected_and_urls_shown_as_text(self):
        """TC-XSS-02: javascript:, data: and vbscript: URLs are rejected; a valid URL with markup stays text."""
        self.register()
        for url in ['javascript:alert(document.cookie)', 'JaVaScRiPt:alert(1)', ' javascript:alert(1)',
                    'java\tscript:alert(1)', 'javascript://example.test/%0Aalert(document.cookie)',
                    'data:text/html,<script>alert(1)</script>', 'vbscript:msgbox(1)']:
            with self.subTest(url=url):
                response = self.post('/vault/new', dict(ENTRY, website_url=url), self.csrf())
                self.assertEqual(response.status_code, 400)
                self.assertNotIn(b'alert(', response.data)
        self.assertEqual(self.count_rows('vault_entries'), 0)
        tricky = 'https://example.test/"><script>alert(1)</script>'
        entry_id = self.add(dict(ENTRY, website_url=tricky))
        for path in ['/vault', f'/vault/{entry_id}', f'/vault/{entry_id}/edit']:
            with self.subTest(path=path):
                page = self.get(path).get_data(as_text=True)
                self.assert_no_injected_markup(page)
                self.assertIn(str(escape(tricky)), page)
                self.assertFalse(any(attrs.get('href') == tricky for _, attrs in Tags(page).tags))

    def test_tc_xss_03_reflected_payloads_are_never_echoed(self):
        """TC-XSS-03: payloads in the URL path and in login/registration forms are not reflected."""
        payload = '<script>alert("reflected")</script>'
        responses = {
            'unknown path': self.get('/' + payload),
            'entry path': self.get('/vault/' + payload),
            'login': self.post('/login', {'login_username': payload, 'master_password': payload + ' padding'},
                               self.csrf('/login')),
            'register name': self.post('/register', {'login_username': payload, 'master_password': MASTER,
                                                     'confirm_password': MASTER}, self.csrf('/register')),
            'register confirm': self.post('/register', {'login_username': 'carol', 'master_password': MASTER,
                                                        'confirm_password': payload + ' padding'},
                                          self.csrf('/register')),
        }
        for name, response in responses.items():
            with self.subTest(request=name):
                self.assertIn(response.status_code, {400, 401, 404})
                self.assertNotIn('reflected', response.get_data(as_text=True))
        self.assertEqual(self.count_rows('users'), 0)

    def test_tc_xss_04_strict_csp_on_every_html_response(self):
        """TC-XSS-04: every HTML response, including error pages, carries a CSP without unsafe-inline/eval."""
        self.register()
        entry_id = self.add()
        responses = {path: self.get(path) for path in
                     ['/', '/vault', '/vault/new', f'/vault/{entry_id}', f'/vault/{entry_id}/edit', '/missing']}
        responses['login page'] = self.get('/login', self.new_client())
        responses['400 page'] = self.post('/vault/new', ENTRY)
        for name, response in responses.items():
            with self.subTest(page=name):
                csp = response.headers['Content-Security-Policy']
                directives = dict(part.strip().split(' ', 1) for part in csp.split(';'))
                self.assertEqual(directives['script-src'], "'self'")
                self.assertEqual(directives['object-src'], "'none'")
                self.assertEqual(directives['base-uri'], "'none'")
                self.assertEqual(directives['frame-ancestors'], "'none'")
                self.assertNotIn('unsafe-inline', csp)
                self.assertNotIn('unsafe-eval', csp)
                self.assertEqual(response.headers['X-Content-Type-Options'], 'nosniff')
                self.assertEqual(response.headers['Content-Type'], 'text/html; charset=utf-8')

    def test_tc_xss_05_templates_never_disable_escaping_or_use_inline_script(self):
        """TC-XSS-05: source audit - no |safe, Markup, autoescape off, inline scripts/handlers or JS files."""
        forbidden = [re.compile(pattern, re.IGNORECASE) for pattern in
                     (r'\|\s*safe\b', r'autoescape\s+false', r'<script', r'\son\w+\s*=', r'\sstyle\s*=',
                      r'javascript:')]
        templates = sorted((ROOT / 'templates').glob('*.html'))
        self.assertGreaterEqual(len(templates), 7)
        for template in templates:
            text = template.read_text(encoding='utf-8')
            for pattern in forbidden:
                with self.subTest(template=template.name, pattern=pattern.pattern):
                    self.assertIsNone(pattern.search(text))
        for source in sorted(ROOT.glob('*.py')):
            text = source.read_text(encoding='utf-8')
            for name in ('Markup(', 'render_template_string(', '|safe'):
                with self.subTest(source=source.name, name=name):
                    self.assertNotIn(name, text)
        self.assertEqual(list((ROOT / 'static').rglob('*.js')), [])

    def test_tc_xss_06_autoescape_is_enforced_for_every_template(self):
        """TC-XSS-06: autoescaping is on for every template, not only for files ending in .html."""
        environment = self.app.jinja_env.overlay(loader=DictLoader({'note.txt': '<p>{{ value}}</p>'}))
        self.assertEqual(environment.get_template('note.txt').render(value='<script>alert(1)</script>'),
                         '<p>&lt;script&gt;alert(1)&lt;/script&gt;</p>')
        self.assertIs(self.app.jinja_env.autoescape, True)

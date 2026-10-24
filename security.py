"""Opaque in-memory sessions, CSRF helpers and bounded login throttling."""
from collections import deque
from contextlib import contextmanager
from dataclasses import dataclass, field, replace
from functools import wraps
import secrets
import threading
import time
from flask import abort, current_app, g, redirect, request, url_for
import database
from validation import ValidationError

COOKIE = "pm_session"


@dataclass
class Session:
    token: str = field(repr=False)
    csrf: str = field(repr=False)
    user_id: int | None
    key: bytes | None = field(repr=False)
    created: float
    last_seen: float


class SessionStore:
    def __init__(self, clock=time.monotonic, capacity=1024, sweep=True):
        self.clock, self.capacity = clock, capacity
        self.records = {}
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        if sweep:
            threading.Thread(target=self._sweeper, daemon=True).start()

    def _expired(self, record, now):
        lifetime = 3600 if record.user_id is not None else 900
        return now - record.created >= lifetime or now - record.last_seen >= 900

    def _purge(self, now):
        for token, record in list(self.records.items()):
            if self._expired(record, now):
                del self.records[token]

    def purge(self):
        with self.lock:
            self._purge(self.clock())

    def _sweeper(self):
        while not self.stopped.wait(60):
            self.purge()

    def close(self):
        self.stopped.set()

    def create(self, user_id=None, key=None):
        with self.lock:
            now = self.clock()
            self._purge(now)
            if len(self.records) >= self.capacity:
                abort(503)
            record = Session(secrets.token_urlsafe(32), secrets.token_urlsafe(32),
                             user_id, key, now, now)
            self.records[record.token] = record
            return replace(record)

    def get(self, token):
        with self.lock:
            now = self.clock()
            record = self.records.get(token)
            if record is None:
                return None
            if self._expired(record, now):
                del self.records[token]
                return None
            record.last_seen = now
            return replace(record)

    def delete(self, token):
        with self.lock:
            self.records.pop(token, None)


class LoginThrottle:
    def __init__(self, clock=time.monotonic):
        self.clock, self.failures = clock, {}
        self.lock = threading.Lock()

    def _prune(self):
        cutoff = self.clock() - 300
        for key, timestamps in list(self.failures.items()):
            while timestamps and timestamps[0] <= cutoff:
                timestamps.popleft()
            if not timestamps:
                del self.failures[key]

    def allowed(self, name, ip):
        with self.lock:
            self._prune()
            keys = (("account", name), ("ip", ip))
            missing = sum(key not in self.failures for key in keys)
            return (len(self.failures) + missing <= 4096
                    and all(len(self.failures.get(key, ())) < 5 for key in keys))

    def failed(self, name, ip):
        with self.lock:
            self._prune()
            for key in (("account", name), ("ip", ip)):
                if key in self.failures or len(self.failures) < 4096:
                    self.failures.setdefault(key, deque(maxlen=5)).append(self.clock())


def get_db():
    if "db" not in g:
        g.db = database.connect(current_app.config["DATABASE"])
    return g.db


def store():
    return current_app.extensions["sessions"]


def issue_session(user_id=None, key=None):
    previous = getattr(g, "pm_session", None)
    if previous is not None:
        store().delete(previous.token)
    g.pm_session = store().create(user_id, key)
    g.new_session_cookie = (g.pm_session.token, 3600 if user_id is not None else 900)
    return g.pm_session


def form_session():
    if g.pm_session is None:
        issue_session()


def form_value(name):
    values = request.form.getlist(name)
    if len(values) != 1:
        raise ValidationError("Invalid form submission.")
    return values[0]


def require_login(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if g.pm_session is None or g.pm_session.user_id is None:
            return redirect(url_for("auth.login"), code=303)
        return view(*args, **kwargs)
    return wrapped


@contextmanager
def kdf_slot():
    semaphore = current_app.extensions["kdf_slots"]
    if not semaphore.acquire(blocking=False):
        abort(503)
    try:
        yield
    finally:
        semaphore.release()


def audit(event, outcome, user_id=None):
    current_app.logger.info("event=%s user_id=%s outcome=%s", event,
                            user_id if user_id is not None else "-", outcome)

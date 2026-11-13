"""Structured security logging: one JSON object per line and never any secrets.

Every record has the same core fields (time, level, event, outcome, user and
request context), so the log can be filtered and parsed by tools. Callers pass
only identifiers and fixed reason codes - never passwords, keys, cookie or CSRF
tokens, or vault entry contents.
"""
from datetime import datetime, timezone
import hashlib
import json
import logging
import os
from pathlib import Path
import sys
import traceback

from flask import current_app, g, has_request_context, request
from flask.logging import default_handler

MAX_PATH = 200
MAX_MESSAGE = 500
MAX_LOG_BYTES = 1024 * 1024


def _timestamp(seconds=None):
    moment = datetime.now(timezone.utc) if seconds is None else datetime.fromtimestamp(seconds, timezone.utc)
    return moment.isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _private_opener(path, flags):
    return os.open(path, flags, 0o600)


class JsonFormatter(logging.Formatter):
    """Audit records are already JSON. Any other record (for example from Flask itself) is
    wrapped, so every line stays one JSON object; tracebacks are never written."""

    def format(self, record):
        if getattr(record, "audit", False):
            return record.getMessage()
        entry = {"ts": _timestamp(record.created), "level": record.levelname, "event": "app_log",
                 "message": record.getMessage()[:MAX_MESSAGE]}
        if record.exc_info and record.exc_info[0] is not None:
            entry["error_type"] = record.exc_info[0].__name__
        return json.dumps(entry, ensure_ascii=True, separators=(",", ":"), default=str)


class JsonLinesFileHandler(logging.Handler):
    """Appends records to a private file and keeps one rotated copy when it is full."""

    def __init__(self, path, max_bytes=MAX_LOG_BYTES):
        super().__init__()
        self.path, self.max_bytes = Path(path), max_bytes
        self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)

    def emit(self, record):
        try:
            line = self.format(record) + "\n"
            if self.path.exists() and self.path.stat().st_size + len(line.encode("utf-8")) > self.max_bytes:
                os.replace(self.path, self.path.with_name(self.path.name + ".1"))
            with open(self.path, "a", encoding="utf-8", newline="\n", opener=_private_opener) as stream:
                stream.write(line)
        except Exception:
            self.handleError(record)


def configure_logging(app):
    """Replace Flask's default text handler with JSON lines on stderr and in LOG_FILE."""
    logger = app.logger
    logger.setLevel(logging.INFO)
    for handler in list(logger.handlers):
        if handler is default_handler or getattr(handler, "json_audit", False):
            logger.removeHandler(handler)
    handlers = [logging.StreamHandler(sys.stderr)]
    if app.config.get("LOG_FILE"):
        handlers.append(JsonLinesFileHandler(app.config["LOG_FILE"]))
    for handler in handlers:
        handler.json_audit = True
        handler.setFormatter(JsonFormatter())
        logger.addHandler(handler)


def session_ref():
    """Short one-way fingerprint linking one session's requests without logging its token."""
    record = getattr(g, "pm_session", None)
    if record is None:
        return None
    return hashlib.sha256(record.token.encode("ascii")).hexdigest()[:12]


def error_location(error):
    """File and line where an exception was raised; its message is never logged."""
    frames = traceback.extract_tb(error.__traceback__)
    return f"{Path(frames[-1].filename).name}:{frames[-1].lineno}" if frames else None


def audit(event, outcome, user_id=None, level=None, **details):
    """Write one structured event. Details may contain only IDs and fixed reason codes."""
    if level is None:
        level = logging.INFO if outcome == "success" else logging.WARNING
    record = {
        "ts": _timestamp(),
        "level": logging.getLevelName(level),
        "event": event,
        "outcome": outcome,
        "user_id": user_id,
    }
    if has_request_context():
        record.update(request_id=g.get("request_id"), session_ref=session_ref(),
                      ip=request.remote_addr, method=request.method, path=request.path[:MAX_PATH])
    record.update(details)
    current_app.logger.log(level, json.dumps(record, ensure_ascii=True, separators=(",", ":"), default=str),
                           extra={"audit": True})

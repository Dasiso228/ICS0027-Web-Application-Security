"""Server-side field limits shared by forms and encrypted records."""

import re
from urllib.parse import urlsplit


class ValidationError(ValueError):
    pass


FIELDS = {"title": 100, "website_url": 2048, "username": 256,
          "password": 1024, "notes": 2000}


def login_name(value):
    value = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9_.-]{3,64}", value):
        raise ValidationError("Use 3-64 letters, digits, dots, underscores or hyphens.")
    return value


def master_password(value):
    if not 15 <= len(value) <= 128 or len(value.encode("utf-8")) > 512:
        raise ValidationError("Use a master passphrase of 15-128 characters (at most 512 UTF-8 bytes).")
    return value


def entry_fields(values):
    if type(values) is not dict or set(values) != set(FIELDS):
        raise ValidationError("Invalid entry fields.")
    for name, limit in FIELDS.items():
        value = values[name]
        if not isinstance(value, str) or len(value) > limit:
            raise ValidationError("One or more fields exceed their allowed length.")
        if name != "notes" and not value:
            raise ValidationError("Title, website URL, username and password are required.")
    url = values["website_url"]
    try:
        parts = urlsplit(url)
        if (url != url.strip() or any(ord(char) < 33 for char in url)
                or parts.scheme not in ("http", "https") or not parts.hostname):
            raise ValueError
        parts.port
    except ValueError:
        raise ValidationError("Use an HTTP or HTTPS website URL with a hostname.") from None
    return values

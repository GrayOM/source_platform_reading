"""Redaction helpers for evidence artifacts.

Evidence artifacts must not store raw secrets, cookies, authorization headers,
or full request/response bodies.
"""
import json
import re
from typing import Any

SENSITIVE_KEY_RE = re.compile(r"(authorization|cookie|set-cookie|token|secret|password|passwd|api[_-]?key|jwt)", re.I)
LONG_SECRET_RE = re.compile(r"\b[A-Za-z0-9+/=_\-]{24,}\b")
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b")
AUTH_HEADER_RE = re.compile(r"(?i)(authorization\s*[:=]\s*bearer\s+)[^\s,;\"']+")


def redact_value(key: str | None, value: Any) -> str:
    text = "" if value is None else str(value)
    if key and SENSITIVE_KEY_RE.search(key):
        return "<redacted>"
    return redact_text(text)


def redact_text(value: str, max_chars: int = 2000) -> str:
    text = value[:max_chars]
    text = JWT_RE.sub("<redacted-jwt>", text)
    text = AUTH_HEADER_RE.sub(r"\1<redacted>", text)
    text = LONG_SECRET_RE.sub("<redacted>", text)
    return text


def redacted_preview(value: Any, max_chars: int = 2000) -> str:
    if isinstance(value, (dict, list)):
        value = _redact_json(value)
        return json.dumps(value, ensure_ascii=False, default=str)[:max_chars]
    return redact_text(str(value), max_chars=max_chars)


def _redact_json(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            str(key): "<redacted>" if SENSITIVE_KEY_RE.search(str(key)) else _redact_json(item)
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact_json(item) for item in value[:50]]
    if isinstance(value, str):
        return redact_text(value)
    return value

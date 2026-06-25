"""Stable finding fingerprint helpers.

Fingerprints intentionally avoid raw secrets, tokens, cookies, and volatile
line-number/query-value details so recurrence can be tracked across scans.
"""
import hashlib
import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlparse

from app.models.finding import VulnType
from app.schemas.finding import FindingCreate


VOLATILE_QUERY_KEYS = {
    "cache",
    "cb",
    "nonce",
    "random",
    "session",
    "sid",
    "t",
    "time",
    "timestamp",
    "token",
    "utm_campaign",
    "utm_content",
    "utm_medium",
    "utm_source",
    "utm_term",
    "v",
    "_",
}
SECRET_TYPES = {VulnType.SECRET_LEAK, VulnType.API_KEY_EXPOSURE, VulnType.JWT_WEAKNESS}
SECRET_KEYS = {
    "secret",
    "token",
    "cookie",
    "authorization",
    "password",
    "api_key",
    "apikey",
    "redacted_secret",
    "value",
}


def generate_finding_fingerprint(finding: FindingCreate) -> str:
    evidence = finding.evidence or {}
    payload = {
        "vulnerability_type": finding.vulnerability_type.value,
        "affected_url": normalize_finding_url(finding.affected_url, evidence),
        "affected_parameter": _clean_text(finding.affected_parameter),
        "source_file": _clean_text(evidence.get("source_file") or evidence.get("source_map_url")),
        "source": _clean_text(evidence.get("source") or evidence.get("source_pattern")),
        "sink": _clean_text(evidence.get("sink") or evidence.get("sink_pattern")),
        "evidence_type": _clean_text(evidence.get("type") or evidence.get("context") or evidence.get("pattern_name")),
        "code": _normalized_code_fingerprint(finding),
    }
    if finding.vulnerability_type in SECRET_TYPES:
        payload["secret_pattern"] = _clean_text(
            evidence.get("pattern_name") or evidence.get("secret_type") or finding.title
        )
        payload.pop("code", None)

    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def normalize_finding_url(url: str | None, evidence: dict[str, Any] | None = None) -> str:
    candidate = url or (evidence or {}).get("endpoint") or (evidence or {}).get("path") or ""
    parsed = urlparse(candidate)
    path = _normalize_path(parsed.path or candidate)
    if "/api/" in path:
        path = _normalize_api_path(path)
    query_keys = sorted(
        key.lower()
        for key, _ in parse_qsl(parsed.query, keep_blank_values=False)
        if key.lower() not in VOLATILE_QUERY_KEYS
    )
    query_part = ",".join(query_keys[:12])
    if parsed.scheme and parsed.netloc:
        host = (parsed.hostname or "").lower()
        port = "" if parsed.port is None else f":{parsed.port}"
        return f"{parsed.scheme.lower()}://{host}{port}{path}?keys={query_part}"
    return f"{path}?keys={query_part}" if query_part else path


def _normalize_path(path: str) -> str:
    lowered = (path or "").strip().lower()
    lowered = re.sub(r"/+", "/", lowered)
    lowered = re.sub(r"/[0-9a-f]{8,}(?=/|$)", "/:id", lowered)
    lowered = re.sub(r"/\d+(?=/|$)", "/:id", lowered)
    return lowered.rstrip("/") or "/"


def _normalize_api_path(path: str) -> str:
    path = re.sub(r"/v\d+(?=/|$)", "/v", path)
    path = re.sub(r"/[0-9a-f-]{20,}(?=/|$)", "/:id", path)
    return path


def _normalized_code_fingerprint(finding: FindingCreate) -> str:
    snippet = finding.code_snippet or (finding.evidence or {}).get("code_snippet") or ""
    if not snippet:
        return ""
    snippet = re.sub(r"(?im)^\s*(?:line\s*)?\d+[:\-\s]+", "", snippet)
    snippet = re.sub(r"['\"][A-Za-z0-9+/=_\-]{16,}['\"]", '"<redacted>"', snippet)
    snippet = re.sub(r"\b[A-Za-z0-9+/=_\-]{24,}\b", "<redacted>", snippet)
    snippet = re.sub(r"\s+", " ", snippet).strip().lower()
    return snippet[:240]


def _clean_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, dict):
        value = {k: v for k, v in value.items() if str(k).lower() not in SECRET_KEYS}
    text = json.dumps(value, sort_keys=True, default=str) if not isinstance(value, str) else value
    text = re.sub(r"\b[A-Za-z0-9+/=_\-]{24,}\b", "<redacted>", text)
    return re.sub(r"\s+", " ", text).strip().lower()[:200]

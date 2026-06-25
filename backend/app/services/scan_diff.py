"""Cross-scan diff helpers for authenticated surface reporting."""
from typing import Any
from urllib.parse import urlparse

from app.models.finding import Finding, Severity, TriageStatus
from app.models.resource import Resource, ResourceType
from app.models.scan import Scan


SENSITIVE_HINT_KEYWORDS = {
    "ADMIN_SURFACE": ("admin", "manage", "dashboard", "console"),
    "INTERNAL_SURFACE": ("internal", "intranet", "staff", "private"),
    "USER_OBJECT_ACCESS": ("user/", "users/", "account", "profile", "member"),
    "GRAPHQL_SURFACE": ("graphql", "gql"),
    "DEBUG_SURFACE": ("debug", "trace", "swagger", "openapi", "actuator"),
    "AUTH_REQUIRED_UNKNOWN": ("auth", "session", "token", "login"),
}


def normalized_origin(url: str) -> str:
    parsed = urlparse(url)
    scheme = (parsed.scheme or "http").lower()
    host = (parsed.hostname or "").lower()
    port = parsed.port
    default_port = (scheme == "http" and port == 80) or (scheme == "https" and port == 443)
    port_part = "" if port is None or default_port else f":{port}"
    return f"{scheme}://{host}{port_part}"


def scan_auth_method(scan: Scan) -> str:
    session = getattr(scan, "session", None)
    auth_method = getattr(session, "auth_method", None)
    return getattr(auth_method, "value", str(auth_method or "none"))


def build_cross_scan_diff(base_scan: Scan, compare_scan: Scan) -> dict[str, Any]:
    """Return resources and findings present in base_scan but absent from compare_scan.

    The report flow calls this with the current scan as base_scan and the selected
    comparison scan as compare_scan. For a Browser Login scan compared to a No Auth
    scan, new_* values represent authenticated-only surface candidates.
    """
    base_resources = list(getattr(base_scan, "resources", []) or [])
    compare_resource_urls = {_normalize_item_url(r.url) for r in getattr(compare_scan, "resources", []) or []}
    new_resources = [r for r in base_resources if _normalize_item_url(r.url) not in compare_resource_urls]

    new_pages = [
        r for r in new_resources
        if r.resource_type == ResourceType.HTML or (r.extra_metadata or {}).get("page")
    ]
    new_js_files = [r for r in new_resources if r.resource_type == ResourceType.JS]
    new_source_maps = [
        r for r in new_resources
        if r.resource_type == ResourceType.SOURCE_MAP or r.url.endswith(".map")
    ]

    base_findings = list(getattr(base_scan, "findings", []) or [])
    compare_finding_keys = {_finding_key(f) for f in getattr(compare_scan, "findings", []) or []}
    new_findings = [f for f in base_findings if _finding_key(f) not in compare_finding_keys]
    new_api_endpoints = _new_api_endpoints(new_findings)
    sensitive_hints = _sensitive_hints(new_api_endpoints)
    high_confidence_new_findings = [
        f for f in new_findings
        if (f.evidence or {}).get("confidence") == "high" or f.severity in {Severity.CRITICAL, Severity.HIGH}
    ]
    verified_new_findings = [f for f in new_findings if f.triage_status == TriageStatus.VERIFIED]
    false_positive_new_findings = [f for f in new_findings if f.triage_status == TriageStatus.FALSE_POSITIVE]

    return {
        "included": True,
        "base_scan_id": str(base_scan.id),
        "compare_scan_id": str(compare_scan.id),
        "target_url": base_scan.target_url,
        "base_auth_method": scan_auth_method(base_scan),
        "compare_auth_method": scan_auth_method(compare_scan),
        "new_pages_count": len(new_pages),
        "new_resources_count": len(new_resources),
        "new_api_endpoints_count": len(new_api_endpoints),
        "new_findings_count": len(new_findings),
        "high_confidence_new_findings_count": len(high_confidence_new_findings),
        "verified_new_findings_count": len(verified_new_findings),
        "false_positive_new_findings_count": len(false_positive_new_findings),
        "sensitive_endpoint_hints": sensitive_hints,
        "new_pages": [_resource_payload(r) for r in new_pages],
        "new_resources": [_resource_payload(r) for r in new_resources],
        "new_js_files": [_resource_payload(r) for r in new_js_files],
        "new_api_endpoints": [
            {
                "endpoint": endpoint,
                "risk_hints": _endpoint_hints(endpoint),
                "verification_required": True,
            }
            for endpoint in new_api_endpoints
        ],
        "new_source_maps": [_resource_payload(r) for r in new_source_maps],
        "new_findings": [_finding_payload(f) for f in new_findings],
    }


def not_included_cross_scan_diff() -> dict[str, bool]:
    return {"included": False}


def _normalize_item_url(url: str | None) -> str:
    return (url or "").rstrip("/")


def _finding_key(finding: Finding) -> tuple[str, str, str]:
    return (
        finding.title.strip().lower(),
        finding.vulnerability_type.value,
        _normalize_item_url(finding.affected_url),
    )


def _resource_payload(resource: Resource) -> dict[str, Any]:
    return {
        "url": resource.url,
        "resource_type": resource.resource_type.value,
        "http_status": resource.http_status,
        "size_bytes": resource.size_bytes,
        "source_map": resource.resource_type == ResourceType.SOURCE_MAP or resource.url.endswith(".map"),
    }


def _finding_payload(finding: Finding) -> dict[str, Any]:
    evidence = finding.evidence or {}
    triage_status = getattr(finding.triage_status, "value", str(finding.triage_status or "candidate"))
    return {
        "id": str(finding.id),
        "title": finding.title,
        "severity": finding.severity.value,
        "confidence": evidence.get("confidence", "unknown"),
        "vulnerability_type": finding.vulnerability_type.value,
        "affected_url": finding.affected_url,
        "triage_status": triage_status,
        "fingerprint": finding.fingerprint,
        "duplicate_of_finding_id": str(finding.duplicate_of_finding_id) if finding.duplicate_of_finding_id else None,
        "recurrence_count": finding.recurrence_count,
        "previous_triage_status": evidence.get("previous_triage_status"),
        "previous_finding_id": evidence.get("previous_finding_id"),
        "previously_verified": bool(evidence.get("previously_verified")),
        "previously_marked_false_positive": bool(evidence.get("previously_marked_false_positive")),
        "verification_required": triage_status in {"candidate", "needs_review"},
    }


def _new_api_endpoints(findings: list[Finding]) -> list[str]:
    endpoints = {
        f.affected_url
        for f in findings
        if f.affected_url and (f.title.lower().startswith("api endpoint") or "/api/" in f.affected_url)
    }
    return sorted(endpoints)


def _endpoint_hints(endpoint: str) -> list[str]:
    lowered = endpoint.lower()
    hints = [
        hint
        for hint, keywords in SENSITIVE_HINT_KEYWORDS.items()
        if any(keyword in lowered for keyword in keywords)
    ]
    if not hints:
        hints.append("AUTH_REQUIRED_UNKNOWN")
    hints.append("VERIFICATION_REQUIRED")
    return sorted(set(hints))


def _sensitive_hints(endpoints: list[str]) -> list[str]:
    hints: set[str] = set()
    for endpoint in endpoints:
        hints.update(_endpoint_hints(endpoint))
    return sorted(hints)

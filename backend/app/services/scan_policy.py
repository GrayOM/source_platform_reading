import ipaddress
import socket
import urllib.parse
from datetime import datetime, timezone
from typing import Any

from app.core.config import get_settings

settings = get_settings()

INTENSITY_DEFAULTS: dict[str, dict[str, Any]] = {
    "low": {
        "max_pages": 30,
        "max_resources": 100,
        "max_depth": 2,
        "max_concurrency": 2,
        "request_delay_ms": 300,
    },
    "normal": {
        "max_pages": 100,
        "max_resources": 300,
        "max_depth": 3,
        "max_concurrency": 4,
        "request_delay_ms": 150,
    },
    "careful": {
        "max_pages": 15,
        "max_resources": 50,
        "max_depth": 1,
        "max_concurrency": 1,
        "request_delay_ms": 500,
    },
}

POLICY_CAPS = {
    "max_pages": 500,
    "max_resources": 1000,
    "max_depth": 5,
    "max_concurrency": 6,
    "request_delay_ms": 5000,
    "request_timeout_ms": 60000,
}

MIN_REQUEST_DELAY_MS = 100
DEFAULT_TIMEOUT_MS = 30000


class ScanPolicyResolver:
    @classmethod
    def resolve(cls, target_url: str, user_policy: dict[str, Any] | None = None, legacy_config: dict[str, Any] | None = None) -> dict[str, Any]:
        raw = dict(user_policy or {})
        legacy = dict(legacy_config or {})
        intensity = str(raw.get("intensity") or "careful").lower()
        if intensity not in INTENSITY_DEFAULTS:
            intensity = "careful"

        policy = {
            "policy_name": raw.get("policy_name") or f"{intensity.title()} default",
            "intensity": intensity,
            **INTENSITY_DEFAULTS[intensity],
            "request_timeout_ms": DEFAULT_TIMEOUT_MS,
            "same_origin_only": True,
            "allowed_hosts": [],
            "excluded_hosts": [],
            "excluded_paths": [],
            "respect_robots_txt": False,
            "allow_private_targets": False,
            "allow_redirect_outside_scope": False,
            "capture_screenshots": True,
            "capture_storage": True,
            "capture_api_flows": True,
            "authorization_confirmed": False,
            "notes": None,
        }

        legacy_map = {
            "max_pages": "max_pages",
            "max_depth": "max_depth",
            "concurrency": "max_concurrency",
            "screenshot_pages": "capture_screenshots",
            "excluded_paths": "excluded_paths",
        }
        for source_key, policy_key in legacy_map.items():
            if source_key in legacy and source_key not in raw:
                policy[policy_key] = legacy[source_key]

        for key, value in raw.items():
            if value is not None:
                policy[key] = value

        target_host = cls._host(target_url)
        allowed_hosts = cls._normalize_hosts(policy.get("allowed_hosts"))
        if target_host and target_host not in allowed_hosts:
            allowed_hosts.insert(0, target_host)

        policy["allowed_hosts"] = allowed_hosts
        policy["excluded_hosts"] = cls._normalize_hosts(policy.get("excluded_hosts"))
        policy["excluded_paths"] = cls._normalize_paths(policy.get("excluded_paths"))
        policy["same_origin_only"] = bool(policy.get("same_origin_only", True))
        policy["allow_redirect_outside_scope"] = bool(policy.get("allow_redirect_outside_scope", False))
        policy["allow_private_targets"] = cls._resolve_private_target_flag(target_host, bool(policy.get("allow_private_targets")))
        policy["capture_screenshots"] = bool(policy.get("capture_screenshots", True))
        policy["capture_storage"] = bool(policy.get("capture_storage", True))
        policy["capture_api_flows"] = bool(policy.get("capture_api_flows", True))
        policy["authorization_confirmed"] = bool(policy.get("authorization_confirmed", False))
        policy["respect_robots_txt"] = bool(policy.get("respect_robots_txt", False))

        for key in ("max_pages", "max_resources", "max_depth", "max_concurrency", "request_timeout_ms"):
            policy[key] = cls._bounded_int(policy.get(key), INTENSITY_DEFAULTS[intensity].get(key, DEFAULT_TIMEOUT_MS), 1, POLICY_CAPS[key])
        policy["request_delay_ms"] = cls._bounded_int(policy.get("request_delay_ms"), INTENSITY_DEFAULTS[intensity]["request_delay_ms"], MIN_REQUEST_DELAY_MS, POLICY_CAPS["request_delay_ms"])
        return policy

    @staticmethod
    def policy_event(event_type: str, url: str | None, reason: str, policy_field: str | None = None, severity: str = "info") -> dict[str, Any]:
        return {
            "event_type": event_type,
            "url": url,
            "reason": reason,
            "policy_field": policy_field,
            "severity": severity,
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    @staticmethod
    def _host(url: str) -> str:
        parsed = urllib.parse.urlparse(url)
        return (parsed.hostname or "").lower().rstrip(".")

    @staticmethod
    def _normalize_hosts(value: Any) -> list[str]:
        if isinstance(value, str):
            items = value.replace("\n", ",").split(",")
        elif isinstance(value, list):
            items = value
        else:
            items = []
        hosts: list[str] = []
        for item in items:
            host = str(item).strip().lower().rstrip(".")
            if not host:
                continue
            parsed = urllib.parse.urlparse(host if "://" in host else f"//{host}")
            normalized = (parsed.hostname or host).lower().rstrip(".")
            if normalized and normalized not in hosts:
                hosts.append(normalized)
        return hosts[:50]

    @staticmethod
    def _normalize_paths(value: Any) -> list[str]:
        if isinstance(value, str):
            items = value.replace("\n", ",").split(",")
        elif isinstance(value, list):
            items = value
        else:
            items = []
        paths: list[str] = []
        for item in items:
            path = str(item).strip()
            if not path:
                continue
            if not path.startswith("/"):
                path = f"/{path}"
            if path not in paths:
                paths.append(path)
        return paths[:100]

    @staticmethod
    def _bounded_int(value: Any, default: int, minimum: int, maximum: int) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError):
            parsed = default
        return max(minimum, min(maximum, parsed))

    @staticmethod
    def _resolve_private_target_flag(host: str, requested: bool) -> bool:
        if not requested:
            return False
        if settings.environment not in ("development", "e2e", "test"):
            return False
        if host in settings.ssrf_allowed_hosts_list:
            return True
        try:
            ip = ipaddress.ip_address(socket.gethostbyname(host))
        except Exception:
            return settings.allow_private_targets
        return settings.allow_private_targets and (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved)

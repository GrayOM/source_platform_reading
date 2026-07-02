"""Base class for all AI analysis agents."""
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path

import anthropic
import structlog

from app.core.config import get_settings
from app.models.finding import FindingStatus, Severity, VulnType
from app.schemas.finding import FindingCreate
from app.services.ai.nvidia import NvidiaNIMClient

settings = get_settings()
log = structlog.get_logger()

AI_SKIP_MESSAGE = "AI analysis skipped - API key not configured"


class AIAnalysisSkipped(RuntimeError):
    """Raised when optional AI analysis is disabled by configuration."""


def is_ai_analysis_configured() -> bool:
    return get_configured_ai_provider() is not None


def get_configured_ai_provider() -> str | None:
    provider = (settings.ai_provider or "auto").strip().lower()
    if provider not in {"auto", "anthropic", "nvidia"}:
        log.warning("ai.provider_unsupported", provider=provider)
        return None

    if provider in {"auto", "nvidia"} and _is_valid_nvidia_key(settings.nvidia_key_for("chat")):
        return "nvidia"
    if provider in {"auto", "anthropic"} and _is_valid_anthropic_key(settings.anthropic_api_key):
        return "anthropic"
    return None


def _is_valid_anthropic_key(key: str | None) -> bool:
    key = (key or "").strip()
    if not key:
        return False

    lowered = key.lower()
    placeholders = {
        "sk-ant-...",
        "sk-ant-test",
        "placeholder",
        "your_api_key",
        "change_me",
        "changeme",
    }
    if lowered in placeholders or "..." in lowered:
        return False

    return key.startswith("sk-ant-api") and len(key) > 40


def _is_valid_nvidia_key(key: str | None) -> bool:
    key = (key or "").strip()
    if not key:
        return False
    lowered = key.lower()
    placeholders = {
        "nvapi-...",
        "nvapi-test",
        "placeholder",
        "your_api_key",
        "change_me",
        "changeme",
    }
    if lowered in placeholders or "..." in lowered:
        return False
    return len(key) > 20


@dataclass
class AgentContext:
    scan_id: str
    target_url: str
    resources: list[dict]
    sitemap: dict
    endpoint_candidates: list[str]
    findings_so_far: list[dict] = field(default_factory=list)
    js_inventory: list[dict] = field(default_factory=list)
    api_map: dict = field(default_factory=dict)


class BaseAgent(ABC):
    name: str = "base"

    def __init__(self):
        self._client = None

    @abstractmethod
    async def analyze(self, context: AgentContext) -> list[FindingCreate]:
        """Run analysis and return findings."""

    def _call_claude(self, system: str, user: str, max_tokens: int = 4096) -> str:
        return self._call_ai(system, user, max_tokens=max_tokens)

    def _call_ai(self, system: str, user: str, max_tokens: int = 4096) -> str:
        provider = get_configured_ai_provider()
        if provider is None:
            raise AIAnalysisSkipped(AI_SKIP_MESSAGE)
        if provider == "nvidia":
            return self._call_nvidia_nim(system, user, max_tokens=max_tokens)
        return self._call_anthropic(system, user, max_tokens=max_tokens)

    def _call_anthropic(self, system: str, user: str, max_tokens: int = 4096) -> str:
        if self._client is None:
            self._client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

        response = self._client.messages.create(
            model=settings.ai_model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return response.content[0].text

    def _call_nvidia_nim(self, system: str, user: str, max_tokens: int = 4096) -> str:
        model = (settings.nvidia_nim_model or "").strip()
        if not model:
            raise AIAnalysisSkipped(AI_SKIP_MESSAGE)
        return NvidiaNIMClient(settings).chat_completion(
            model=model,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            max_tokens=min(max_tokens, settings.ai_max_tokens),
            temperature=0.1,
            extra_body={"chat_template_kwargs": {"thinking": settings.nvidia_thinking}},
        )

    def _parse_findings_json(self, raw: str, agent_name: str) -> list[FindingCreate]:
        """Extract and parse JSON findings array from model output."""
        try:
            start = raw.find("[")
            end = raw.rfind("]") + 1
            if start == -1 or end == 0:
                return []
            data = json.loads(raw[start:end])
            findings = []
            for item in data:
                try:
                    findings.append(FindingCreate(
                        agent_name=agent_name,
                        vulnerability_type=VulnType(item.get("type", "other")),
                        severity=Severity(item.get("severity", "info")),
                        title=str(item.get("title", "Untitled"))[:500],
                        description=str(item.get("description", "")),
                        affected_url=item.get("affected_url"),
                        affected_parameter=item.get("parameter"),
                        evidence=item.get("evidence", {}),
                        code_snippet=item.get("code_snippet") or item.get("evidence", {}).get("code_snippet"),
                        poc=item.get("poc", {}),
                        reproduction_steps=item.get("reproduction_steps", []),
                        cwe_id=item.get("cwe_id"),
                        cvss_score=item.get("cvss_score"),
                        cvss_vector=item.get("cvss_vector"),
                        owasp_category=item.get("owasp_category"),
                        recommendation=item.get("recommendation", ""),
                    ))
                except Exception as exc:
                    log.warning("agent.parse_finding_failed", agent=agent_name, error=str(exc), item=item)
            return findings
        except json.JSONDecodeError as exc:
            log.warning("agent.json_parse_failed", agent=agent_name, error=str(exc))
            return []

    def _read_resource(self, file_path: str | None, max_bytes: int = 200_000) -> str:
        if not file_path:
            return ""
        try:
            return Path(file_path).read_bytes()[:max_bytes].decode("utf-8", errors="replace")
        except Exception:
            return ""

    @staticmethod
    def _findings_json_schema() -> str:
        return """
Return ONLY a valid JSON array. Each element must be:
{
  "type": "<vuln_type>",         // one of: xss, sql_injection, secret_leak, idor, auth_bypass,
                                  //  missing_auth, sensitive_data, insecure_storage,
                                  //  api_key_exposure, jwt_weakness, csrf, open_redirect,
                                  //  path_traversal, ssrf, business_logic, other
  "severity": "<level>",         // critical | high | medium | low | info
  "title": "<short title>",
  "description": "<markdown description with evidence>",
  "affected_url": "<url or null>",
  "parameter": "<param name or null>",
  "evidence": {
    "code_snippet": "<relevant code, max 500 chars>",
    "line_number": <int or null>,
    "context": "<explanation>"
  },
  "cwe_id": <int or null>,
  "cvss_score": <0.0-10.0 or null>,
  "cvss_vector": "<vector string or null>",
  "owasp_category": "<e.g. A01:2021 or null>",
  "recommendation": "<actionable fix>"
}
If no findings, return [].
"""

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

settings = get_settings()
log = structlog.get_logger()


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
        self._client = anthropic.Anthropic(api_key=settings.anthropic_api_key)

    @abstractmethod
    async def analyze(self, context: AgentContext) -> list[FindingCreate]:
        """Run analysis and return findings."""

    def _call_claude(self, system: str, user: str, max_tokens: int = 4096) -> str:
        response = self._client.messages.create(
            model=settings.ai_model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        return response.content[0].text

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

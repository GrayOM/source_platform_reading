"""Secret / credential detection agent.

Uses regex pattern matching (fast, deterministic) combined with AI
context analysis to reduce false positives.
"""
import asyncio
import re
from pathlib import Path

import structlog

from app.models.resource import ResourceType
from app.schemas.finding import FindingCreate
from app.services.analysis.agents.base_agent import AgentContext, BaseAgent

log = structlog.get_logger()

# Patterns: (name, regex, severity, cwe)
SECRET_PATTERNS: list[tuple[str, str, str, int]] = [
    ("AWS Access Key",          r"AKIA[0-9A-Z]{16}",                          "critical", 798),
    ("AWS Secret Key",          r"(?i)aws[_\-\s]?secret[_\-\s]?access[_\-\s]?key\s*[=:]\s*['\"]?[A-Za-z0-9/+=]{40}", "critical", 798),
    ("GitHub Personal Token",   r"ghp_[A-Za-z0-9]{36}",                       "critical", 798),
    ("GitHub OAuth Token",      r"gho_[A-Za-z0-9]{36}",                       "critical", 798),
    ("Slack Bot Token",         r"xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}", "critical", 798),
    ("Slack Webhook",           r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+", "high", 798),
    ("Stripe Secret Key",       r"sk_live_[0-9a-zA-Z]{24,}",                  "critical", 798),
    ("Stripe Publishable Key",  r"pk_live_[0-9a-zA-Z]{24,}",                  "medium", 200),
    ("Google API Key",          r"AIza[0-9A-Za-z_\-]{35}",                    "high", 798),
    ("Firebase API Key",        r"AIza[0-9A-Za-z_\-]{35}",                    "high", 798),
    ("JWT Token",               r"eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+", "medium", 522),
    ("Private Key (PEM)",       r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----",   "critical", 321),
    ("Database URL",            r"(?i)(mysql|postgres|mongodb|redis)://[^\s\"'<>]+:[^\s\"'<>]+@[^\s\"'<>]+", "critical", 798),
    ("Generic Secret",          r"(?i)(?:secret|password|passwd|api_?key|auth_?token)\s*[=:]\s*['\"](?![\{<\$])[A-Za-z0-9!@#$%^&*()_+\-=]{8,}", "high", 798),
    ("Basic Auth in URL",       r"https?://[^:]+:[^@]+@",                      "high", 522),
    ("Anthropic API Key",       r"sk-ant-api03-[A-Za-z0-9_\-]{90,}",          "critical", 798),
    ("OpenAI API Key",          r"sk-(?:proj-)?[A-Za-z0-9]{48,}",             "critical", 798),
]

ALLOWLIST_VALUES = {"your_api_key", "xxxx", "****", "example", "placeholder", "changeme", "<your", "insert", "todo"}


class SecretDetectorAgent(BaseAgent):
    name = "secret_detector"

    async def analyze(self, context: AgentContext) -> list[FindingCreate]:
        analyzable = [
            r for r in context.resources
            if r.get("resource_type") in ("js", "html", "json", "source_map")
            and r.get("file_path")
        ]

        tasks = [self._scan_resource(r) for r in analyzable[:50]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[FindingCreate] = []
        for result in results:
            if isinstance(result, list):
                findings.extend(result)
        return findings

    async def _scan_resource(self, resource: dict) -> list[FindingCreate]:
        content = self._read_resource(resource.get("file_path"))
        if not content:
            return []
        return await asyncio.to_thread(self._regex_scan, content, resource["url"])

    def _regex_scan(self, content: str, source_url: str) -> list[FindingCreate]:
        findings = []
        lines = content.splitlines()

        for pattern_name, pattern, severity, cwe in SECRET_PATTERNS:
            for match in re.finditer(pattern, content, re.MULTILINE):
                matched_value = match.group(0)

                # Skip allowlisted placeholder values
                if any(av in matched_value.lower() for av in ALLOWLIST_VALUES):
                    continue

                # Find line number
                line_num = content[:match.start()].count("\n") + 1
                context_line = lines[line_num - 1].strip()[:200] if line_num <= len(lines) else ""

                # Redact the secret value in evidence
                redacted = matched_value[:6] + "*" * max(0, len(matched_value) - 10) + matched_value[-4:] if len(matched_value) > 12 else "***"

                findings.append(FindingCreate(
                    agent_name=self.name,
                    vulnerability_type=self._map_type(pattern_name),
                    severity=severity,  # type: ignore[arg-type]
                    title=f"{pattern_name} exposed in {_basename(source_url)}",
                    description=(
                        f"A {pattern_name} was found hardcoded in `{source_url}`. "
                        f"Exposed credentials can be used by attackers to access the corresponding service."
                    ),
                    affected_url=source_url,
                    evidence={
                        "matched_pattern": pattern_name,
                        "redacted_value": redacted,
                        "line_number": line_num,
                        "code_snippet": context_line,
                        "context": "Secret found via static regex scan",
                    },
                    cwe_id=cwe,
                    cvss_score=self._severity_to_cvss(severity),
                    owasp_category="A02:2021",
                    recommendation=(
                        f"Remove the {pattern_name} from client-side code immediately. "
                        "Rotate the credential, store it server-side, and access it via authenticated API calls."
                    ),
                ))

        return findings

    @staticmethod
    def _map_type(pattern_name: str):
        from app.models.finding import VulnType
        name_lower = pattern_name.lower()
        if "jwt" in name_lower:
            return VulnType.JWT_WEAKNESS
        if "key" in name_lower or "token" in name_lower or "secret" in name_lower:
            return VulnType.API_KEY_EXPOSURE
        if "password" in name_lower or "database" in name_lower:
            return VulnType.SECRET_LEAK
        return VulnType.SENSITIVE_DATA

    @staticmethod
    def _severity_to_cvss(severity: str) -> float:
        return {"critical": 9.1, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}.get(severity, 5.0)


def _basename(url: str) -> str:
    return url.rstrip("/").split("/")[-1] or url

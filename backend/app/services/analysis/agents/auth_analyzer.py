"""Authentication & Authorization analysis agent.

Analyzes discovered endpoints and JS code to find:
- Unauthenticated access to sensitive endpoints
- Horizontal/vertical privilege escalation (IDOR)
- JWT weaknesses (alg:none, weak secrets, missing exp validation)
- Missing CSRF protection
- OAuth misconfigurations
- Session management issues
"""
import asyncio

import structlog

from app.schemas.finding import FindingCreate
from app.services.analysis.agents.base_agent import AgentContext, BaseAgent

log = structlog.get_logger()


class AuthAnalyzerAgent(BaseAgent):
    name = "auth_analyzer"

    async def analyze(self, context: AgentContext) -> list[FindingCreate]:
        endpoint_sample = context.endpoint_candidates[:100]
        api_map_summary = "\n".join(f"- {ep}" for ep in endpoint_sample)

        # Collect auth-relevant JS snippets
        auth_snippets = await asyncio.to_thread(self._extract_auth_snippets, context.resources)

        # Build prompt with known findings for context
        prior_secrets = [
            f for f in context.findings_so_far
            if f.get("vulnerability_type") in ("jwt_weakness", "api_key_exposure", "secret_leak")
        ]
        prior_summary = "\n".join(f"- [{f['severity']}] {f['title']}" for f in prior_secrets[:10])

        system = f"""You are a senior penetration tester specializing in authentication and authorization vulnerabilities.

Target: {context.target_url}

Known discovered endpoints ({len(endpoint_sample)} sample):
{api_map_summary or "(none discovered)"}

Auth-relevant code snippets:
{auth_snippets[:8000] or "(none found)"}

Previously found secrets/tokens:
{prior_summary or "(none)"}

Analyze for:
1. Endpoints that appear to handle sensitive actions but may lack auth (e.g., /api/admin, /api/user/*, /api/order/*)
2. JWT handling issues: no signature verification, alg:none, weak secrets, no expiry
3. IDOR patterns: user IDs in URL parameters, predictable object references
4. CSRF: forms/fetch calls modifying state without CSRF tokens
5. Missing security headers (report as informational)
6. OAuth redirect_uri validation issues
7. Password/token handling: cleartext storage, weak comparison

{self._findings_json_schema()}"""

        user = (
            f"Based on the endpoint inventory and code analysis for {context.target_url}, "
            "identify authentication and authorization vulnerabilities."
        )

        findings_raw = await asyncio.to_thread(self._call_claude, system, user, max_tokens=6000)
        return self._parse_findings_json(findings_raw, self.name)

    def _extract_auth_snippets(self, resources: list[dict]) -> str:
        import re
        AUTH_PATTERNS = [
            r"(?i)(localStorage|sessionStorage)\.(set|get)Item\(['\"](?:token|auth|jwt|session|user)",
            r"(?i)Authorization\s*[:=]\s*['\"]?(Bearer|Basic)",
            r"(?i)jwt\.(verify|decode|sign)",
            r"(?i)(login|logout|register|auth|authenticate|token|session)",
            r"(?i)role\s*[=!]=",
            r"(?i)isAdmin|isAuthenticated|hasPermission|checkAuth",
        ]
        combined = re.compile("|".join(AUTH_PATTERNS))
        snippets = []
        for r in resources:
            if r.get("resource_type") not in ("js", "html"):
                continue
            content = self._read_resource(r.get("file_path"), max_bytes=100_000)
            for match in re.finditer(combined, content):
                start = max(0, match.start() - 100)
                end = min(len(content), match.end() + 200)
                snippets.append(f"// from {r['url']}\n{content[start:end].strip()}")
                if len(snippets) >= 20:
                    return "\n\n---\n\n".join(snippets)

        return "\n\n---\n\n".join(snippets)

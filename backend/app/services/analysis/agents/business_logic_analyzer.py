"""Business logic vulnerability analyzer.

Analyzes the full picture of collected data to find:
- Price manipulation (client-side pricing, negative quantities)
- Workflow bypass (skipping required steps)
- Race conditions (no idempotency, dual submission)
- Privilege escalation via parameter tampering
- Mass assignment vulnerabilities
"""
import asyncio

from app.schemas.finding import FindingCreate
from app.services.analysis.agents.base_agent import AgentContext, BaseAgent


class BusinessLogicAgent(BaseAgent):
    name = "business_logic"

    async def analyze(self, context: AgentContext) -> list[FindingCreate]:
        # Summarize all prior findings
        prior_findings_summary = "\n".join(
            f"- [{f.get('severity', '?')}] {f.get('vulnerability_type', '?')}: {f.get('title', '?')}"
            for f in context.findings_so_far[:30]
        )

        # Sample interesting API endpoints
        api_endpoints = context.api_map.get("endpoints", context.endpoint_candidates)[:80]
        endpoint_list = "\n".join(f"- {ep}" for ep in api_endpoints)

        # Get HTML forms for workflow analysis
        form_analysis = await asyncio.to_thread(self._extract_forms, context.resources)

        system = f"""You are a senior application security researcher specializing in business logic vulnerabilities.

Target application: {context.target_url}
API endpoints ({len(api_endpoints)} discovered):
{endpoint_list or "(none)"}

HTML forms and workflows:
{form_analysis[:4000] or "(none found)"}

Previously discovered vulnerabilities:
{prior_findings_summary or "(none)"}

Analyze for business logic flaws:
1. Client-side price/discount calculation: look for price, amount, discount, coupon in JS
2. Workflow bypass: multi-step processes (checkout, enrollment, verification) where steps can be skipped
3. Race conditions: endpoints that modify state without idempotency keys
4. Parameter tampering: role, userID, accountId, planId passed as user-controlled parameters
5. Mass assignment: APIs accepting object spread or all fields without allowlist
6. Negative values / integer overflow in financial operations
7. Insecure direct object references in REST paths (/api/orders/:id, /api/users/:id)

For each finding, explain the attack scenario clearly.
{self._findings_json_schema()}"""

        user = f"Analyze the {context.target_url} application for business logic vulnerabilities."
        findings_raw = await asyncio.to_thread(self._call_claude, system, user, max_tokens=6000)
        return self._parse_findings_json(findings_raw, self.name)

    def _extract_forms(self, resources: list[dict]) -> str:
        import re
        snippets = []
        form_re = re.compile(r"<form[^>]*>.*?</form>", re.DOTALL | re.IGNORECASE)
        for r in resources:
            if r.get("resource_type") != "html":
                continue
            content = self._read_resource(r.get("file_path"), max_bytes=100_000)
            for match in form_re.finditer(content):
                form_html = match.group(0)[:500]
                snippets.append(f"// {r['url']}\n{form_html}")
                if len(snippets) >= 10:
                    return "\n\n".join(snippets)
        return "\n\n".join(snippets)

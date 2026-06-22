"""API endpoint mapping agent.

Extracts a structured inventory of all API endpoints from:
- XHR/Fetch intercepted URLs
- JavaScript source code (fetch(), axios, $.ajax, etc.)
- HTML form actions
- Source maps (deobfuscated paths)
- OpenAPI / Swagger JSON files
"""
import asyncio
import json
import re
from dataclasses import dataclass, field

import structlog

from app.schemas.finding import FindingCreate
from app.models.finding import Severity, VulnType
from app.services.analysis.agents.base_agent import AgentContext, BaseAgent

log = structlog.get_logger()


@dataclass
class APIEndpoint:
    url: str
    method: str = "UNKNOWN"
    parameters: list[str] = field(default_factory=list)
    auth_required: bool | None = None
    source: str = ""


class APIMapperAgent(BaseAgent):
    name = "api_mapper"

    async def analyze(self, context: AgentContext) -> list[FindingCreate]:
        # Extract endpoints from JS source
        js_endpoints = await asyncio.to_thread(self._extract_from_js, context.resources)

        # Merge with intercepted XHR/Fetch endpoints
        all_endpoints = set(context.endpoint_candidates) | set(js_endpoints)

        endpoint_findings = self._endpoint_exposure_findings(context.target_url, list(all_endpoints))
        source_map_findings = await asyncio.to_thread(self._source_map_findings, context.resources)

        # Check for Swagger/OpenAPI discovery
        swagger_findings = await asyncio.to_thread(
            self._check_swagger_exposure, context.target_url, list(all_endpoints)
        )

        # Store the API map in context for other agents
        context.api_map = {
            "endpoints": list(all_endpoints),
            "js_extracted": js_endpoints,
            "intercepted": context.endpoint_candidates,
        }

        return endpoint_findings + source_map_findings + swagger_findings

    def _extract_from_js(self, resources: list[dict]) -> list[str]:
        endpoints: set[str] = set()
        patterns = [
            r"""(?:fetch|axios\.(?:get|post|put|delete|patch))\s*\(\s*[`'"](\/[^`'"]+)[`'"]""",
            r"""(?:url|endpoint|path|route)\s*[:=]\s*[`'"](\/api\/[^`'"<>\s]+)[`'"]""",
            r"""[`'"](\/api\/v\d+\/[^`'"<>\s]+)[`'"]""",
            r"""[`'"](\/graphql[^`'"<>\s]*)[`'"]""",
            r"""\$\.(?:get|post|ajax)\s*\(\s*[`'"](\/[^`'"]+)[`'"]""",
        ]
        combined = re.compile("|".join(patterns))
        for r in resources:
            if r.get("resource_type") not in ("js",):
                continue
            content = self._read_resource(r.get("file_path"), max_bytes=200_000)
            for match in combined.finditer(content):
                path = next((g for g in match.groups() if g), None)
                if path and len(path) > 2:
                    endpoints.add(path)
        return list(endpoints)

    def _check_swagger_exposure(self, target_url: str, endpoints: list[str]) -> list[FindingCreate]:
        """Check if Swagger UI or OpenAPI JSON is exposed."""
        import httpx
        swagger_paths = [
            "/swagger-ui.html", "/swagger-ui/", "/api-docs", "/api/docs",
            "/openapi.json", "/swagger.json", "/v2/api-docs", "/v3/api-docs",
        ]
        findings = []
        from urllib.parse import urljoin
        for path in swagger_paths:
            url = urljoin(target_url, path)
            if url in endpoints:
                findings.append(FindingCreate(
                    agent_name=self.name,
                    vulnerability_type="sensitive_data",  # type: ignore[arg-type]
                    severity="medium",  # type: ignore[arg-type]
                    title=f"API Documentation Exposed: {path}",
                    description=(
                        f"The API documentation endpoint `{url}` appears to be publicly accessible. "
                        "Exposed Swagger/OpenAPI docs can significantly aid attackers in understanding "
                        "the API surface, authentication requirements, and parameter names."
                    ),
                    affected_url=url,
                    evidence={"path": path, "context": "Found in intercepted endpoint inventory"},
                    cwe_id=200,
                    cvss_score=5.3,
                    owasp_category="A01:2021",
                    recommendation="Restrict API documentation to internal networks or authenticated users.",
                ))
        return findings

    def _endpoint_exposure_findings(self, target_url: str, endpoints: list[str]) -> list[FindingCreate]:
        interesting = sorted({
            ep for ep in endpoints
            if any(marker in ep.lower() for marker in ("/api/", "/graphql", "/admin", "/internal", "/v1", "/v2"))
        })
        findings = []
        for ep in interesting[:25]:
            findings.append(FindingCreate(
                agent_name=self.name,
                vulnerability_type=VulnType.SENSITIVE_DATA,
                severity=Severity.INFO,
                title="API endpoint exposed in client-side flow",
                description="An API endpoint candidate was discovered from browser traffic or JavaScript source.",
                affected_url=ep,
                evidence={"endpoint": ep, "source": "crawler/js endpoint inventory"},
                code_snippet=ep,
                poc={
                    "type": "api_endpoint_verification",
                    "curl": f"curl -i '{ep}'",
                    "auth_header": "Add Authorization header if the endpoint requires authentication.",
                    "response_check": "Verify status code, response schema, and whether unauthenticated or low-privilege access is allowed.",
                    "authorization_review_required": True,
                },
                reproduction_steps=[
                    "Replay the endpoint in a controlled test environment.",
                    "Compare unauthenticated, low-privilege, and authorized responses.",
                    "Confirm that sensitive data or state-changing actions require proper authorization.",
                ],
                cwe_id=200,
                cvss_score=0.0,
                owasp_category="A01:2021",
                recommendation="Ensure endpoint authorization is enforced server-side and hide only nonessential implementation details from client bundles.",
            ))
        return findings

    def _source_map_findings(self, resources: list[dict]) -> list[FindingCreate]:
        findings = []
        for resource in resources:
            if resource.get("resource_type") == "source_map" or resource.get("url", "").endswith(".map"):
                content = self._read_resource(resource.get("file_path"), max_bytes=50_000)
                snippet = content[:500]
                findings.append(FindingCreate(
                    agent_name=self.name,
                    vulnerability_type=VulnType.SENSITIVE_DATA,
                    severity=Severity.LOW,
                    title="Source map file is accessible",
                    description="A JavaScript source map was downloaded successfully and may expose original source paths or comments.",
                    affected_url=resource.get("url"),
                    evidence={
                        "source_map_url": resource.get("url"),
                        "code_snippet": snippet,
                        "has_sources": '"sources"' in content,
                    },
                    code_snippet=snippet,
                    poc={
                        "type": "source_map_verification",
                        "source_mapping_url": resource.get("url"),
                        "map_url": resource.get("url"),
                        "original_paths_exposed": '"sources"' in content,
                        "remediation": "Do not publish production source maps publicly unless intentionally required.",
                    },
                    reproduction_steps=[
                        f"Request the source map URL: {resource.get('url')}",
                        "Confirm that the HTTP response is accessible and contains source map JSON.",
                        "Inspect the `sources` and `sourcesContent` fields for original paths or source code.",
                    ],
                    cwe_id=200,
                    cvss_score=3.1,
                    owasp_category="A05:2021",
                    recommendation="Disable public source map publication or restrict access to authenticated engineering users.",
                ))
        return findings

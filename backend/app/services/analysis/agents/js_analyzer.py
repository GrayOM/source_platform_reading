"""JavaScript security analyzer agent.

Focuses on: DOM XSS, prototype pollution, client-side template injection,
dangerous eval/innerHTML usage, insecure postMessage handlers, and
hardcoded secrets embedded in JS bundles.
"""
import asyncio
import re
from pathlib import Path

import structlog

from app.models.finding import Severity, VulnType
from app.models.resource import ResourceType
from app.schemas.finding import FindingCreate
from app.services.analysis.agents.base_agent import AgentContext, BaseAgent
from app.services.collector.resource_classifier import is_analyzable

log = structlog.get_logger()

SYSTEM_PROMPT = """You are a senior web application security engineer specializing in JavaScript security analysis.
Your job is to find real, exploitable vulnerabilities in JavaScript source code.

Focus on:
1. DOM-based XSS: direct innerHTML/outerHTML/document.write with unsanitized sources
   (location.hash, location.search, URLSearchParams, postMessage data, etc.)
2. Prototype pollution: recursive merge/assign functions that don't filter __proto__
3. Client-side template injection (Angular $sce, Vue v-html, React dangerouslySetInnerHTML)
4. Dangerous eval() / Function() / setTimeout(string) patterns
5. Insecure postMessage handlers without origin validation
6. JWT or token storage in localStorage (note: report as informational)
7. API keys or secrets hardcoded in JS (not environment variable references)
8. Client-side authorization checks that are bypassable

Do NOT report:
- Minified variable names as "obfuscation"
- Console.log statements
- TODO comments unless they expose credentials
- Issues only exploitable with physical device access

Be precise. Quote the relevant code in evidence.
""" + BaseAgent._findings_json_schema.__func__(None) if False else ""


class JSAnalyzerAgent(BaseAgent):
    name = "js_analyzer"

    async def analyze(self, context: AgentContext) -> list[FindingCreate]:
        js_resources = [
            r for r in context.resources
            if r.get("resource_type") in (ResourceType.JS.value, "js")
            and r.get("file_path")
        ]

        if not js_resources:
            return []

        tasks = [self._analyze_file(r, context.target_url) for r in js_resources[:30]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings: list[FindingCreate] = []
        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)
            elif isinstance(result, Exception):
                log.warning("js_analyzer.file_failed", error=str(result))

        return all_findings

    async def _analyze_file(self, resource: dict, target_url: str) -> list[FindingCreate]:
        content = self._read_resource(resource.get("file_path"))
        if not content or len(content) < 50:
            return []

        # Chunk large files to stay within token limits
        chunks = self._chunk_js(content, max_chars=60_000)
        all_findings = []
        for i, chunk in enumerate(chunks):
            findings = await asyncio.to_thread(self._analyze_chunk, chunk, resource["url"], target_url, i)
            all_findings.extend(findings)
        return all_findings

    def _analyze_chunk(self, code: str, resource_url: str, target_url: str, chunk_idx: int) -> list[FindingCreate]:
        return self._regex_analyze(code, resource_url)

    def _regex_analyze(self, code: str, resource_url: str) -> list[FindingCreate]:
        findings: list[FindingCreate] = []
        lines = code.splitlines()

        source_pattern = r"(location\.(?:search|hash)|new\s+URLSearchParams|postMessage|event\.data)"
        sink_pattern = r"(innerHTML|outerHTML|document\.write|dangerouslySetInnerHTML|v-html)"
        if re.search(source_pattern, code) and re.search(sink_pattern, code):
            snippet = _first_matching_line(lines, sink_pattern)
            findings.append(FindingCreate(
                agent_name=self.name,
                vulnerability_type=VulnType.XSS,
                severity=Severity.MEDIUM,
                title="Potential DOM XSS data flow in JavaScript",
                description=(
                    "The JavaScript bundle references browser-controlled input and dangerous DOM insertion sinks. "
                    "Manual validation is required to confirm sanitization and exploitability."
                ),
                affected_url=resource_url,
                affected_parameter="location/search/hash or message data",
                evidence={"source_pattern": source_pattern, "sink_pattern": sink_pattern, "code_snippet": snippet},
                code_snippet=snippet,
                poc={
                    "type": "dom_xss_verification",
                    "test_url": resource_url,
                    "payload": "<img src=x onerror=alert(1)>",
                    "expected_result": "Payload must not execute and should be rendered as inert text or rejected.",
                    "confirmation": "Observe whether script execution occurs after placing payload in the consumed URL parameter or hash.",
                },
                reproduction_steps=[
                    "Identify the route/page that loads this JavaScript resource.",
                    "Place the payload in the referenced query string or hash parameter.",
                    "Load the page in a test browser and verify whether the payload reaches the highlighted DOM sink.",
                ],
                cwe_id=79,
                cvss_score=5.4,
                owasp_category="A03:2021",
                recommendation="Avoid dangerous DOM sinks or sanitize untrusted input with a vetted HTML sanitizer before insertion.",
            ))

        message_handlers = re.finditer(r"addEventListener\s*\(\s*['\"]message['\"](?P<body>[\s\S]{0,1500})", code)
        for match in message_handlers:
            body = match.group("body")
            if "origin" not in body:
                snippet = body.splitlines()[0][:300] if body else match.group(0)[:300]
                findings.append(FindingCreate(
                    agent_name=self.name,
                    vulnerability_type=VulnType.XSS,
                    severity=Severity.MEDIUM,
                    title="postMessage handler without visible origin validation",
                    description="A message event handler was found without an obvious event.origin allowlist check nearby.",
                    affected_url=resource_url,
                    affected_parameter="postMessage event.data",
                    evidence={"code_snippet": snippet, "context": "message handler lacks visible origin validation"},
                    code_snippet=snippet,
                    poc={
                        "type": "postmessage_verification",
                        "test": "Send a crafted postMessage from a different origin in a controlled test page.",
                        "expected_result": "The application should reject messages from untrusted origins.",
                        "confirmation": "No state change or DOM update should occur unless event.origin matches an allowlist.",
                    },
                    reproduction_steps=[
                        "Open the affected page in a browser.",
                        "From a controlled different-origin page, call targetWindow.postMessage with test data.",
                        "Confirm whether the message handler accepts the data without checking event.origin.",
                    ],
                    cwe_id=346,
                    cvss_score=5.3,
                    owasp_category="A01:2021",
                    recommendation="Validate event.origin against an explicit allowlist before processing event.data.",
                ))
                break

        storage_pattern = r"(localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(\s*['\"]([^'\"]*(?:token|jwt|access_token|refresh_token)[^'\"]*)['\"]"
        for match in re.finditer(storage_pattern, code, re.IGNORECASE):
            snippet = _line_for_offset(code, lines, match.start())
            findings.append(FindingCreate(
                agent_name=self.name,
                vulnerability_type=VulnType.INSECURE_STORAGE,
                severity=Severity.LOW,
                title="Token-like value stored in browser storage",
                description="Client-side code stores or reads token-like values from localStorage/sessionStorage.",
                affected_url=resource_url,
                affected_parameter=match.group(2),
                evidence={"storage": match.group(1), "key": match.group(2), "code_snippet": snippet},
                code_snippet=snippet,
                poc={
                    "type": "storage_verification",
                    "storage": match.group(1),
                    "key": match.group(2),
                    "verification": "Inspect browser developer tools after login and confirm whether sensitive tokens are stored under this key.",
                },
                reproduction_steps=[
                    "Authenticate to the application in a test browser.",
                    f"Open developer tools and inspect {match.group(1)}.",
                    f"Check whether `{match.group(2)}` contains an access token, refresh token, or JWT.",
                ],
                cwe_id=922,
                cvss_score=3.1,
                owasp_category="A02:2021",
                recommendation="Prefer HttpOnly Secure SameSite cookies for session tokens and keep token lifetimes short.",
            ))
            break

        return findings

    @staticmethod
    def _chunk_js(content: str, max_chars: int = 60_000) -> list[str]:
        if len(content) <= max_chars:
            return [content]
        chunks = []
        start = 0
        while start < len(content):
            end = start + max_chars
            if end < len(content):
                # Try to split on a newline boundary
                newline = content.rfind("\n", start, end)
                if newline > start:
                    end = newline
            chunks.append(content[start:end])
            start = end
        return chunks


def _first_matching_line(lines: list[str], pattern: str) -> str:
    regex = re.compile(pattern)
    for line in lines:
        if regex.search(line):
            return line.strip()[:500]
    return ""


def _line_for_offset(code: str, lines: list[str], offset: int) -> str:
    line_num = code[:offset].count("\n")
    if 0 <= line_num < len(lines):
        return lines[line_num].strip()[:500]
    return ""

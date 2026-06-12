"""JavaScript security analyzer agent.

Focuses on: DOM XSS, prototype pollution, client-side template injection,
dangerous eval/innerHTML usage, insecure postMessage handlers, and
hardcoded secrets embedded in JS bundles.
"""
import asyncio
from pathlib import Path

import structlog

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
        system = f"""You are a senior web security engineer.
Analyze the following JavaScript code for security vulnerabilities.
Target application: {target_url}
Resource URL: {resource_url}
{chr(10).join([
    "Find real, exploitable vulnerabilities. Be specific with code evidence.",
    "Return ONLY a JSON array of findings or [].",
    "",
    "JSON schema per finding:",
    self._findings_json_schema(),
])}"""

        user = f"```javascript\n{code}\n```"
        try:
            raw = self._call_claude(system=system, user=user)
            return self._parse_findings_json(raw, self.name)
        except Exception as exc:
            log.warning("js_analyzer.claude_error", error=str(exc))
            return []

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

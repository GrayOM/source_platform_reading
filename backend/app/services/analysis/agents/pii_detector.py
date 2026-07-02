"""PII detection agent backed by NVIDIA GLiNER PII."""

import asyncio

import structlog

from app.models.finding import Severity, VulnType
from app.schemas.finding import FindingCreate
from app.services.ai.nvidia import NvidiaNIMClient, PIIEntity
from app.services.analysis.agents.base_agent import AgentContext, BaseAgent, AIAnalysisSkipped

log = structlog.get_logger()


class PIIDetectorAgent(BaseAgent):
    name = "pii_detector"

    async def analyze(self, context: AgentContext) -> list[FindingCreate]:
        resources = [
            resource for resource in context.resources
            if resource.get("resource_type") in ("html", "json", "js")
            and resource.get("file_path")
        ]
        if not resources:
            return []

        tasks = [self._scan_resource(resource) for resource in resources[:30]]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        findings: list[FindingCreate] = []
        for resource, result in zip(resources[:30], results):
            if isinstance(result, AIAnalysisSkipped):
                log.info("pii_detector.skipped", reason=str(result))
                break
            if isinstance(result, Exception):
                log.warning("pii_detector.resource_failed", url=resource.get("url"), error=str(result))
                continue
            if result:
                findings.append(self._finding_for_resource(resource, result))
        return findings

    async def _scan_resource(self, resource: dict) -> list[PIIEntity]:
        content = self._read_resource(resource.get("file_path"), max_bytes=40_000)
        if not content.strip():
            return []
        client = NvidiaNIMClient()
        if not client.settings.nvidia_key_for("pii"):
            raise AIAnalysisSkipped("NVIDIA PII API key is not configured")
        return await asyncio.to_thread(client.detect_pii, content[:12_000])

    def _finding_for_resource(self, resource: dict, entities: list[PIIEntity]) -> FindingCreate:
        unique_entities = _dedupe_entities(entities)[:20]
        labels = sorted({entity.label for entity in unique_entities})
        redacted_entities = [
            {
                "label": entity.label,
                "redacted_value": _redact(entity.text),
                "start": entity.start,
                "end": entity.end,
                "score": entity.score,
            }
            for entity in unique_entities
        ]
        severity = Severity.MEDIUM if len(unique_entities) >= 3 else Severity.LOW
        return FindingCreate(
            agent_name=self.name,
            vulnerability_type=VulnType.SENSITIVE_DATA,
            severity=severity,
            title="Potential personal data exposed in collected resource",
            description=(
                "NVIDIA GLiNER PII detected personal-data-like entities in a resource collected during the scan. "
                "Review whether this data is expected, properly authorized, and minimized."
            ),
            affected_url=resource.get("url"),
            evidence={
                "entity_count": len(unique_entities),
                "labels": labels,
                "entities": redacted_entities,
                "model": NvidiaNIMClient().settings.nvidia_pii_model,
            },
            poc={
                "type": "pii_exposure_review",
                "resource": resource.get("url"),
                "entity_labels": labels,
                "verification": "Confirm the data is returned only to authorized users and is necessary for the workflow.",
            },
            reproduction_steps=[
                "Open the affected resource in the scan evidence.",
                "Review the redacted entity labels and surrounding response context.",
                "Confirm whether personal data exposure is expected and access-controlled.",
            ],
            cwe_id=200,
            cvss_score=4.3 if severity == Severity.MEDIUM else 2.7,
            owasp_category="A01:2021",
            recommendation="Minimize personal data in client-visible resources and enforce authorization on data-bearing endpoints.",
        )


def _dedupe_entities(entities: list[PIIEntity]) -> list[PIIEntity]:
    seen: set[tuple[str, str]] = set()
    deduped: list[PIIEntity] = []
    for entity in entities:
        key = (entity.label.lower(), entity.text.lower())
        if key in seen:
            continue
        seen.add(key)
        deduped.append(entity)
    return deduped


def _redact(value: str) -> str:
    value = value.strip()
    if len(value) <= 2:
        return "*" * len(value)
    if "@" in value:
        local, _, domain = value.partition("@")
        return f"{local[:1]}***@{domain[:1]}***"
    return f"{value[:1]}{'*' * max(1, len(value) - 2)}{value[-1:]}"

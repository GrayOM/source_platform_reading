"""Evidence artifact creation and finding-link helpers."""
import uuid
from typing import Any

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import EvidenceArtifactType, Finding, FindingEvidenceArtifact, VulnType
from app.models.resource import Resource, ResourceType
from app.services.evidence.redaction import redacted_preview

log = structlog.get_logger()


def artifact_type_from_value(value: str | EvidenceArtifactType) -> EvidenceArtifactType:
    if isinstance(value, EvidenceArtifactType):
        return value
    for artifact_type in EvidenceArtifactType:
        if value in (artifact_type.value, artifact_type.name):
            return artifact_type
    raise ValueError(f"Unsupported artifact type: {value}")


def build_resource_artifact(scan_id: uuid.UUID, resource: Resource) -> FindingEvidenceArtifact:
    artifact_type = EvidenceArtifactType.SOURCE_MAP if resource.resource_type == ResourceType.SOURCE_MAP else EvidenceArtifactType.SOURCE_FILE
    return FindingEvidenceArtifact(
        scan_id=scan_id,
        artifact_type=artifact_type,
        title=f"Collected {resource.resource_type.value} resource",
        description=f"Resource collected during crawl: {resource.url}",
        file_path=resource.file_path,
        url=resource.url,
        status_code=resource.http_status,
        content_type=resource.mime_type,
        content_hash=resource.content_hash,
        auth_context=(resource.extra_metadata or {}).get("auth_context") or "anonymous",
        extra_metadata={
            "resource_id": str(resource.id),
            "source_map_url": resource.source_map_url,
            "discovered_on_page": resource.discovered_on_page,
        },
    )


def build_candidate_artifact(scan_id: uuid.UUID, data: dict[str, Any]) -> FindingEvidenceArtifact:
    return FindingEvidenceArtifact(
        scan_id=scan_id,
        artifact_type=artifact_type_from_value(data["artifact_type"]),
        title=data.get("title") or "Evidence artifact",
        description=data.get("description"),
        file_path=data.get("file_path"),
        url=data.get("url"),
        http_method=data.get("http_method"),
        status_code=data.get("status_code"),
        content_type=data.get("content_type"),
        content_hash=data.get("content_hash"),
        redacted_body_preview=data.get("redacted_body_preview"),
        line_start=data.get("line_start"),
        line_end=data.get("line_end"),
        storage_type=data.get("storage_type"),
        storage_key=data.get("storage_key"),
        redacted_value=data.get("redacted_value"),
        screenshot_path=data.get("screenshot_path"),
        auth_context=data.get("auth_context") or "anonymous",
        verification_required=bool(data.get("verification_required", False)),
        extra_metadata=data.get("metadata") or {},
    )


async def link_artifacts_for_finding(db: AsyncSession, finding: Finding) -> None:
    try:
        result = await db.execute(
            select(FindingEvidenceArtifact).where(FindingEvidenceArtifact.scan_id == finding.scan_id)
        )
        artifacts = list(result.scalars().all())
        selected = _select_existing_artifacts(finding, artifacts)
        for artifact in selected:
            if artifact.finding_id is None:
                artifact.finding_id = finding.id
        snippet = _snippet_artifact(finding)
        if snippet:
            db.add(snippet)
        reproduction = _reproduction_artifact(finding)
        if reproduction:
            db.add(reproduction)
    except Exception as exc:
        log.warning("evidence.link_failed", finding_id=str(finding.id), error=str(exc))


def _select_existing_artifacts(finding: Finding, artifacts: list[FindingEvidenceArtifact]) -> list[FindingEvidenceArtifact]:
    affected_url = finding.affected_url or ""
    resource_id = str(finding.resource_id) if finding.resource_id else None
    selected: list[FindingEvidenceArtifact] = []
    for artifact in artifacts:
        if resource_id and (artifact.extra_metadata or {}).get("resource_id") == resource_id:
            selected.append(artifact)
            continue
        if affected_url and (artifact.url == affected_url or affected_url in (artifact.url or "") or (artifact.url or "") in affected_url):
            selected.append(artifact)
            continue
        if finding.vulnerability_type == VulnType.INSECURE_STORAGE and artifact.artifact_type == EvidenceArtifactType.STORAGE_SNAPSHOT:
            selected.append(artifact)
            continue
        if finding.vulnerability_type == VulnType.SENSITIVE_DATA and artifact.artifact_type in {EvidenceArtifactType.API_FLOW, EvidenceArtifactType.SOURCE_MAP}:
            if affected_url and artifact.url and (affected_url == artifact.url or affected_url in artifact.url):
                selected.append(artifact)
    return selected[:8]


def _snippet_artifact(finding: Finding) -> FindingEvidenceArtifact | None:
    snippet = finding.code_snippet or (finding.evidence or {}).get("code_snippet")
    if not snippet:
        return None
    line = (finding.evidence or {}).get("line_number")
    try:
        line = int(line) if line else None
    except (TypeError, ValueError):
        line = None
    return FindingEvidenceArtifact(
        scan_id=finding.scan_id,
        finding_id=finding.id,
        artifact_type=EvidenceArtifactType.CODE_SNIPPET,
        title="Finding code snippet",
        description="Redacted code snippet used as finding evidence.",
        url=finding.affected_url,
        redacted_body_preview=redacted_preview(snippet),
        line_start=line,
        line_end=line,
        auth_context="anonymous",
    )


def _reproduction_artifact(finding: Finding) -> FindingEvidenceArtifact | None:
    if not finding.reproduction_steps:
        return None
    return FindingEvidenceArtifact(
        scan_id=finding.scan_id,
        finding_id=finding.id,
        artifact_type=EvidenceArtifactType.REPRODUCTION,
        title="Reproduction guidance",
        description="Manual reproduction steps recorded for the finding.",
        url=finding.affected_url,
        redacted_body_preview=redacted_preview(finding.reproduction_steps),
        verification_required=True,
        auth_context="anonymous",
    )

"""Multi-agent analysis orchestrator.

Runs agents in two rounds:
  Round 1 (parallel): JSAnalyzerAgent, SecretDetectorAgent, APIMapperAgent
  Round 2 (sequential, context-aware): AuthAnalyzerAgent, BusinessLogicAgent
"""
import asyncio
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path

import structlog
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, Severity, TriageStatus, VulnType
from app.models.resource import Resource
from app.models.scan import Scan
from app.schemas.finding import FindingCreate
from app.services.analysis.agents.api_mapper import APIMapperAgent
from app.services.analysis.agents.auth_analyzer import AuthAnalyzerAgent
from app.services.analysis.agents.base_agent import AI_SKIP_MESSAGE, AIAnalysisSkipped, AgentContext, is_ai_analysis_configured
from app.services.analysis.agents.business_logic_analyzer import BusinessLogicAgent
from app.services.analysis.agents.js_analyzer import JSAnalyzerAgent
from app.services.analysis.agents.pii_detector import PIIDetectorAgent
from app.services.analysis.agents.secret_detector import SecretDetectorAgent
from app.services.evidence.artifacts import link_artifacts_for_finding
from app.services.finding_fingerprint import generate_finding_fingerprint
from app.services.scan_diff import normalized_origin

log = structlog.get_logger()


class AnalysisOrchestrator:
    def __init__(self, scan_id: str, target_url: str, db: AsyncSession, progress_callback=None):
        self.scan_id = scan_id
        self.target_url = target_url
        self.db = db
        self.progress_callback = progress_callback

        self._agents_round1 = [
            JSAnalyzerAgent(),
            SecretDetectorAgent(),
            APIMapperAgent(),
            PIIDetectorAgent(),
        ]
        self._agents_round2 = [
            AuthAnalyzerAgent(),
            BusinessLogicAgent(),
        ]

    async def run(self, resources: list[Resource], crawl_data: dict) -> list[Finding]:
        resource_dicts = [
            {
                "id": str(r.id),
                "url": r.url,
                "resource_type": r.resource_type.value,
                "file_path": r.file_path,
                "mime_type": r.mime_type,
                "is_minified": r.is_minified,
            }
            for r in resources
        ]

        context = AgentContext(
            scan_id=self.scan_id,
            target_url=self.target_url,
            resources=resource_dicts,
            sitemap=crawl_data.get("sitemap", {}),
            endpoint_candidates=crawl_data.get("endpoint_candidates", []),
        )

        all_findings: list[FindingCreate] = []

        # Round 1: parallel
        log.info("analysis.round1_start", scan_id=self.scan_id)
        if self.progress_callback:
            self.progress_callback("Starting parallel analysis agents (Round 1)...")

        round1_tasks = [agent.analyze(context) for agent in self._agents_round1]
        round1_results = await asyncio.gather(*round1_tasks, return_exceptions=True)

        for agent, result in zip(self._agents_round1, round1_results):
            if isinstance(result, Exception):
                log.error("analysis.agent_failed", agent=agent.name, error=str(result))
            elif isinstance(result, list):
                log.info("analysis.agent_done", agent=agent.name, count=len(result))
                all_findings.extend(result)

        # Persist round 1 findings and update context
        saved_round1 = await self._persist_findings(all_findings)
        context.findings_so_far = [
            {"severity": f.severity.value, "vulnerability_type": f.vulnerability_type.value, "title": f.title}
            for f in saved_round1
        ]

        # Round 2: sequential (each agent sees prior findings)
        if not is_ai_analysis_configured():
            log.info("analysis.round2_skipped", scan_id=self.scan_id, reason=AI_SKIP_MESSAGE)
            if self.progress_callback:
                self.progress_callback(AI_SKIP_MESSAGE)
            await self._persist_findings([self._ai_skip_finding()])
        else:
            log.info("analysis.round2_start", scan_id=self.scan_id)
            if self.progress_callback:
                self.progress_callback("Running context-aware agents (Round 2)...")

            for agent in self._agents_round2:
                try:
                    new_findings = await agent.analyze(context)
                    log.info("analysis.agent_done", agent=agent.name, count=len(new_findings))
                    saved = await self._persist_findings(new_findings)
                    context.findings_so_far.extend(
                        {"severity": f.severity.value, "vulnerability_type": f.vulnerability_type.value, "title": f.title}
                        for f in saved
                    )
                except AIAnalysisSkipped as exc:
                    log.info("analysis.agent_skipped", agent=agent.name, reason=str(exc))
                except Exception as exc:
                    log.error("analysis.agent_failed", agent=agent.name, error=str(exc))

        from sqlalchemy import select
        result = await self.db.execute(
            select(Finding).where(Finding.scan_id == uuid.UUID(self.scan_id))
        )
        return list(result.scalars().all())

    def _ai_skip_finding(self) -> FindingCreate:
        return FindingCreate(
            agent_name="ai_round2",
            vulnerability_type=VulnType.OTHER,
            severity=Severity.INFO,
            title=AI_SKIP_MESSAGE,
            description=(
                "Optional AI round2 analysis was skipped because no supported AI provider API key "
                "is configured or the configured key still looks like a placeholder. "
                "Deterministic round1 analysis completed normally."
            ),
            affected_url=self.target_url,
            evidence={"reason": "No valid AI provider API key is configured"},
            recommendation=(
                "Set NVIDIA_API_KEY for NVIDIA NIM or ANTHROPIC_API_KEY for Anthropic only when "
                "optional AI round2 analysis is needed."
            ),
        )

    async def _persist_findings(self, findings: list[FindingCreate]) -> list[Finding]:
        if not findings:
            return []
        saved = []
        deduped: dict[str, FindingCreate] = {}
        for fc in findings:
            fingerprint = generate_finding_fingerprint(fc)
            if fingerprint not in deduped:
                deduped[fingerprint] = fc

        scan = await self.db.get(Scan, uuid.UUID(self.scan_id))
        project_id = scan.project_id if scan else None
        target_origin = normalized_origin(self.target_url)
        now = datetime.now(timezone.utc)

        for fingerprint, fc in deduped.items():
            previous = await self._previous_finding(fingerprint, project_id, target_origin)
            evidence = dict(fc.evidence or {})
            duplicate_of_finding_id = None
            recurrence_count = 1
            first_seen_at = now
            if previous:
                duplicate_of_finding_id = previous.duplicate_of_finding_id or previous.id
                recurrence_count = max(2, (previous.recurrence_count or 1) + 1)
                first_seen_at = previous.first_seen_at or previous.created_at or now
                previous_triage = getattr(previous.triage_status, "value", str(previous.triage_status or "candidate"))
                evidence.update(
                    {
                        "previous_triage_status": previous_triage,
                        "previous_finding_id": str(previous.id),
                        "recurring": True,
                        "verification_required": previous_triage not in {TriageStatus.VERIFIED.value},
                    }
                )
                if previous_triage == TriageStatus.FALSE_POSITIVE.value:
                    evidence.update(
                        {
                            "previously_marked_false_positive": True,
                            "verification_required": True,
                        }
                    )
                if previous_triage == TriageStatus.VERIFIED.value:
                    evidence.update(
                        {
                            "previously_verified": True,
                            "verification_required": False,
                        }
                    )
                previous.recurrence_count = max(previous.recurrence_count or 1, recurrence_count)
                previous.last_seen_at = now

            finding = Finding(
                scan_id=uuid.UUID(self.scan_id),
                **fc.model_copy(update={"evidence": evidence}).model_dump(),
                fingerprint=fingerprint,
                duplicate_of_finding_id=duplicate_of_finding_id,
                recurrence_count=recurrence_count,
                first_seen_at=first_seen_at,
                last_seen_at=now,
            )
            self.db.add(finding)
            saved.append(finding)
        await self.db.flush()
        for finding in saved:
            await link_artifacts_for_finding(self.db, finding)
        await self.db.flush()
        return saved

    async def _previous_finding(self, fingerprint: str, project_id: uuid.UUID | None, target_origin: str) -> Finding | None:
        if not project_id:
            return None
        result = await self.db.execute(
            select(Finding, Scan.target_url)
            .join(Scan, Scan.id == Finding.scan_id)
            .where(
                Finding.fingerprint == fingerprint,
                Finding.scan_id != uuid.UUID(self.scan_id),
                Scan.project_id == project_id,
            )
            .order_by(Finding.first_seen_at.asc().nulls_last(), Finding.created_at.asc())
        )
        for finding, target_url in result.all():
            if normalized_origin(target_url) == target_origin:
                return finding
        return None

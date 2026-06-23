"""Multi-agent analysis orchestrator.

Runs agents in two rounds:
  Round 1 (parallel): JSAnalyzerAgent, SecretDetectorAgent, APIMapperAgent
  Round 2 (sequential, context-aware): AuthAnalyzerAgent, BusinessLogicAgent
"""
import asyncio
import uuid
from dataclasses import asdict, dataclass
from pathlib import Path

import structlog
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.finding import Finding, Severity, VulnType
from app.models.resource import Resource
from app.schemas.finding import FindingCreate
from app.services.analysis.agents.api_mapper import APIMapperAgent
from app.services.analysis.agents.auth_analyzer import AuthAnalyzerAgent
from app.services.analysis.agents.base_agent import AI_SKIP_MESSAGE, AIAnalysisSkipped, AgentContext, is_ai_analysis_configured
from app.services.analysis.agents.business_logic_analyzer import BusinessLogicAgent
from app.services.analysis.agents.js_analyzer import JSAnalyzerAgent
from app.services.analysis.agents.secret_detector import SecretDetectorAgent

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
                "Optional AI round2 analysis was skipped because ANTHROPIC_API_KEY is empty "
                "or still set to a placeholder value. Deterministic round1 analysis completed normally."
            ),
            affected_url=self.target_url,
            evidence={"reason": "ANTHROPIC_API_KEY is not configured"},
            recommendation="Set a valid ANTHROPIC_API_KEY only when optional AI round2 analysis is needed.",
        )

    async def _persist_findings(self, findings: list[FindingCreate]) -> list[Finding]:
        if not findings:
            return []
        saved = []
        for fc in findings:
            finding = Finding(
                scan_id=uuid.UUID(self.scan_id),
                **fc.model_dump(),
            )
            self.db.add(finding)
            saved.append(finding)
        await self.db.flush()
        return saved

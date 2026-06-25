import json
import uuid
from datetime import datetime, timezone

import pytest

from app.core.database import AsyncSessionLocal
from app.models.finding import Finding, Severity, TriageStatus, VulnType
from app.models.project import Project
from app.models.report import ReportFormat, ReportType
from app.models.scan import Scan, ScanStatus
from app.models.user import User
from app.schemas.finding import FindingCreate
from app.services.analysis.orchestrator import AnalysisOrchestrator
from app.services.finding_fingerprint import generate_finding_fingerprint
from app.services.report.report_engine import ReportEngine


def _finding(url: str, vuln_type: VulnType = VulnType.XSS, evidence: dict | None = None, code: str | None = None) -> FindingCreate:
    return FindingCreate(
        agent_name="fingerprint_test",
        vulnerability_type=vuln_type,
        severity=Severity.HIGH,
        title="Stable finding candidate",
        description="A stable finding candidate.",
        affected_url=url,
        evidence=evidence or {"source": "location.search", "sink": "innerHTML", "evidence_type": "dom_xss"},
        code_snippet=code or "42: output.innerHTML = location.search",
        recommendation="Review and remediate.",
    )


async def _create_project_and_scan(email: str, target_url: str = "https://example.com/app") -> tuple[uuid.UUID, uuid.UUID]:
    async with AsyncSessionLocal() as db:
        user = User(email=email, password_hash="hash", full_name="Fingerprint User")
        project = Project(owner=user, name=f"Fingerprint {email}")
        scan = Scan(
            project=project,
            target_url=target_url,
            status=ScanStatus.COMPLETED,
            progress=100,
            started_at=datetime.now(timezone.utc),
        )
        db.add(scan)
        await db.flush()
        project_id, scan_id = project.id, scan.id
        await db.commit()
        return project_id, scan_id


@pytest.mark.asyncio
async def test_same_scan_duplicate_fingerprint_is_persisted_once():
    _, scan_id = await _create_project_and_scan("fingerprint-dedup@example.com")
    async with AsyncSessionLocal() as db:
        orchestrator = AnalysisOrchestrator(str(scan_id), "https://example.com/app", db)
        saved = await orchestrator._persist_findings(
            [
                _finding("https://example.com/app?timestamp=1"),
                _finding("https://example.com/app?timestamp=2"),
            ]
        )
        await db.commit()

    assert len(saved) == 1
    assert saved[0].fingerprint


@pytest.mark.asyncio
async def test_scan_between_same_fingerprint_is_marked_recurring():
    project_id, old_scan_id = await _create_project_and_scan("fingerprint-recurring@example.com")
    fc = _finding("https://example.com/app?timestamp=1")
    fingerprint = generate_finding_fingerprint(fc)
    async with AsyncSessionLocal() as db:
        old = Finding(
            scan_id=old_scan_id,
            **fc.model_dump(),
            fingerprint=fingerprint,
            recurrence_count=1,
            first_seen_at=datetime.now(timezone.utc),
            last_seen_at=datetime.now(timezone.utc),
        )
        db.add(old)
        await db.commit()
        old_id = old.id

    async with AsyncSessionLocal() as db:
        new_scan = Scan(project_id=project_id, target_url="https://example.com/app", status=ScanStatus.COMPLETED)
        db.add(new_scan)
        await db.flush()
        orchestrator = AnalysisOrchestrator(str(new_scan.id), "https://example.com/app", db)
        saved = await orchestrator._persist_findings([_finding("https://example.com/app?timestamp=9")])
        await db.commit()

    assert len(saved) == 1
    assert saved[0].duplicate_of_finding_id == old_id
    assert saved[0].recurrence_count == 2
    assert saved[0].previous_finding_id == str(old_id)


@pytest.mark.asyncio
async def test_previous_false_positive_reappears_as_candidate_with_metadata():
    project_id, old_scan_id = await _create_project_and_scan("fingerprint-fp@example.com")
    fc = _finding("https://example.com/app")
    fingerprint = generate_finding_fingerprint(fc)
    async with AsyncSessionLocal() as db:
        previous = Finding(
            scan_id=old_scan_id,
            **fc.model_dump(),
            fingerprint=fingerprint,
            triage_status=TriageStatus.FALSE_POSITIVE,
        )
        db.add(previous)
        await db.commit()

    async with AsyncSessionLocal() as db:
        new_scan = Scan(project_id=project_id, target_url="https://example.com/app", status=ScanStatus.COMPLETED)
        db.add(new_scan)
        await db.flush()
        saved = await AnalysisOrchestrator(str(new_scan.id), "https://example.com/app", db)._persist_findings([fc])
        await db.commit()

    assert saved[0].triage_status == TriageStatus.CANDIDATE
    assert saved[0].previously_marked_false_positive is True
    assert saved[0].previous_triage_status == "false_positive"
    assert saved[0].evidence["verification_required"] is True


@pytest.mark.asyncio
async def test_previous_verified_reappears_with_reference_metadata():
    project_id, old_scan_id = await _create_project_and_scan("fingerprint-verified@example.com")
    fc = _finding("https://example.com/app")
    fingerprint = generate_finding_fingerprint(fc)
    async with AsyncSessionLocal() as db:
        previous = Finding(
            scan_id=old_scan_id,
            **fc.model_dump(),
            fingerprint=fingerprint,
            triage_status=TriageStatus.VERIFIED,
        )
        db.add(previous)
        await db.commit()

    async with AsyncSessionLocal() as db:
        new_scan = Scan(project_id=project_id, target_url="https://example.com/app", status=ScanStatus.COMPLETED)
        db.add(new_scan)
        await db.flush()
        saved = await AnalysisOrchestrator(str(new_scan.id), "https://example.com/app", db)._persist_findings([fc])
        await db.commit()

    assert saved[0].triage_status == TriageStatus.CANDIDATE
    assert saved[0].previously_verified is True
    assert saved[0].previous_triage_status == "verified"
    assert saved[0].evidence["verification_required"] is False


def test_secret_raw_value_does_not_change_fingerprint():
    first = _finding(
        "https://example.com/app.js",
        VulnType.SECRET_LEAK,
        evidence={"pattern_name": "Generic Secret", "redacted_secret": "sk-live-1111", "code_snippet": "api_key='sk-live-1111'"},
        code="api_key='sk-live-1111'",
    )
    second = _finding(
        "https://example.com/app.js",
        VulnType.SECRET_LEAK,
        evidence={"pattern_name": "Generic Secret", "redacted_secret": "sk-live-2222", "code_snippet": "api_key='sk-live-2222'"},
        code="api_key='sk-live-2222'",
    )

    assert generate_finding_fingerprint(first) == generate_finding_fingerprint(second)
    assert "sk-live" not in generate_finding_fingerprint(first)


def test_volatile_query_values_do_not_change_fingerprint():
    assert generate_finding_fingerprint(_finding("https://example.com/app?timestamp=1&debug=true")) == generate_finding_fingerprint(
        _finding("https://example.com/app?timestamp=2&debug=false")
    )


def test_report_summary_includes_recurrence_counts(tmp_path):
    scan = Scan(id=uuid.uuid4(), project_id=uuid.uuid4(), target_url="https://example.com", status=ScanStatus.COMPLETED)
    new_payload = _finding("https://example.com/new").model_dump()
    recurring_payload = _finding("https://example.com/old").model_dump()
    recurring_payload["evidence"] = {"previously_verified": True, "previous_triage_status": "verified"}
    new = Finding(
        id=uuid.uuid4(),
        scan_id=scan.id,
        **new_payload,
        fingerprint="a" * 64,
        recurrence_count=1,
    )
    recurring = Finding(
        id=uuid.uuid4(),
        scan_id=scan.id,
        **recurring_payload,
        fingerprint="b" * 64,
        duplicate_of_finding_id=uuid.uuid4(),
        recurrence_count=2,
    )
    path = ReportEngine(scan, [new, recurring], tmp_path).generate(ReportFormat.JSON, ReportType.FULL)
    payload = json.loads(path.read_text(encoding="utf-8"))

    assert payload["recurrence_summary"]["new_findings_count"] == 1
    assert payload["recurrence_summary"]["recurring_findings_count"] == 1
    assert payload["recurrence_summary"]["previously_verified_count"] == 1
    assert payload["findings"][1]["previous_triage_status"] == "verified"

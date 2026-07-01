"""Report generation engine.

Supports: PDF, HTML, JSON, Markdown
Formats: KISA, OWASP, Executive Summary, Technical Full
"""
import json
import tempfile
from datetime import datetime, timezone
from pathlib import Path

import structlog
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.config import get_settings
from app.models.finding import EvidenceArtifactType, Finding, FindingEvidenceArtifact, Severity, TriageStatus
from app.models.resource import ResourceType
from app.models.report import ReportFormat, ReportType
from app.models.scan import Scan
from app.services.scan_diff import not_included_cross_scan_diff

settings = get_settings()
log = structlog.get_logger()

TEMPLATES_DIR = Path(__file__).parent / "templates"

jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
)


class ReportEngine:
    def __init__(
        self,
        scan: Scan,
        findings: list[Finding],
        output_dir: Path,
        cross_scan_diff: dict | None = None,
        report_metadata: dict | None = None,
    ):
        self.scan = scan
        self.findings = findings
        self.cross_scan_diff = cross_scan_diff or not_included_cross_scan_diff()
        self.report_metadata = report_metadata or {}
        self.output_dir = output_dir
        self.last_pdf_error: str | None = None
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, fmt: ReportFormat, report_type: ReportType) -> Path:
        context = self._build_context(report_type)

        if fmt == ReportFormat.JSON:
            return self._write_json(context)
        elif fmt == ReportFormat.MARKDOWN:
            return self._write_markdown(context, report_type)
        elif fmt == ReportFormat.HTML:
            return self._write_html(context, report_type)
        elif fmt == ReportFormat.PDF:
            return self._write_pdf(context, report_type)
        else:
            raise ValueError(f"Unsupported format: {fmt}")

    def _build_context(self, report_type: ReportType) -> dict:
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        sorted_findings = sorted(self.findings, key=lambda f: severity_order.get(f.severity, 5))
        triage_counts = self._build_triage_counts()
        recurrence_counts = self._build_recurrence_counts()
        verified_findings = [f for f in sorted_findings if self._triage_status_value(f) == TriageStatus.VERIFIED.value]
        false_positive_findings = [f for f in sorted_findings if self._triage_status_value(f) == TriageStatus.FALSE_POSITIVE.value]
        previously_false_positive_findings = [f for f in sorted_findings if self._bool_meta(f, "previously_marked_false_positive")]
        security_findings = [f for f in sorted_findings if self._triage_status_value(f) != TriageStatus.FALSE_POSITIVE.value]

        counts = {s.value: 0 for s in Severity}
        for f in self.findings:
            counts[f.severity.value] += 1

        risk_score = self._calculate_risk_score()
        resources = list(getattr(self.scan, "resources", []) or [])
        pages = [r for r in resources if r.resource_type == ResourceType.HTML or (r.extra_metadata or {}).get("page")]
        js_files = [r for r in resources if r.resource_type == ResourceType.JS]
        api_candidates = [
            f.affected_url for f in sorted_findings
            if f.title.lower().startswith("api endpoint") and f.affected_url
        ]
        source_maps = [r for r in resources if r.resource_type == ResourceType.SOURCE_MAP or r.url.endswith(".map")]
        artifacts = list(getattr(self.scan, "evidence_artifacts", []) or [])
        if not artifacts:
            for finding in self.findings:
                artifacts.extend(getattr(finding, "evidence_artifacts", []) or [])
        artifact_index = [self._artifact_payload(artifact) for artifact in artifacts]
        artifacts_by_finding = self._artifacts_by_finding(artifact_index)
        report_metadata = self._build_report_metadata()
        scan_config = getattr(self.scan, "config", None) or {}
        scan_policy = dict(scan_config.get("scan_policy") or {})
        policy_events = list(scan_config.get("policy_events") or [])
        policy_event_counts: dict[str, int] = {}
        for event in policy_events:
            event_type = str(event.get("event_type") or "unknown")
            policy_event_counts[event_type] = policy_event_counts.get(event_type, 0) + 1
        finding_confidence = {str(f.id): self._finding_confidence(f) for f in sorted_findings}
        finding_auth_context = {
            str(f.id): self._finding_auth_context(f, artifacts_by_finding.get(str(f.id), []))
            for f in sorted_findings
        }
        finding_verification_required = {
            str(f.id): self._finding_verification_required(f, artifacts_by_finding.get(str(f.id), []))
            for f in sorted_findings
        }
        finding_status_phrase = {str(f.id): self._finding_status_phrase(f) for f in sorted_findings}
        confidence_counts = self._build_confidence_counts(finding_confidence)

        return {
            "scan": self.scan,
            "target_url": self.scan.target_url,
            "scan_id": str(self.scan.id),
            "project_name": getattr(getattr(self.scan, "project", None), "name", "N/A"),
            "auth_method": self._scan_auth_method(),
            "report_metadata": report_metadata,
            "scan_policy": scan_policy,
            "policy_events": policy_events,
            "policy_event_counts": policy_event_counts,
            "report_type": report_type.value,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings": sorted_findings,
            "findings_count": len(self.findings),
            "security_findings": security_findings,
            "verified_findings": verified_findings,
            "false_positive_findings": false_positive_findings,
            "previously_false_positive_findings": previously_false_positive_findings,
            "triage_counts": triage_counts,
            "recurrence_counts": recurrence_counts,
            "severity_counts": counts,
            "confidence_counts": confidence_counts,
            "pages": pages,
            "resources": resources,
            "js_files": js_files,
            "api_candidates": api_candidates,
            "source_maps": source_maps,
            "risk_score": risk_score,
            "risk_level": self._risk_level(risk_score),
            "owasp_mapping": self._build_owasp_mapping(),
            "kisa_categories": self._build_kisa_categories(),
            "executive_summary": self._build_executive_summary(counts, risk_score),
            "cross_scan_diff": self.cross_scan_diff,
            "artifacts": artifacts,
            "artifact_index": artifact_index,
            "artifacts_by_finding": artifacts_by_finding,
            "evidence_summary": self._build_evidence_summary(artifacts),
            "finding_confidence": finding_confidence,
            "finding_auth_context": finding_auth_context,
            "finding_verification_required": finding_verification_required,
            "finding_status_phrase": finding_status_phrase,
            "authenticated_findings_count": sum(1 for value in finding_auth_context.values() if value == "authenticated"),
            "kisa_report_metadata": self._build_kisa_report_metadata(
                report_metadata=report_metadata,
                triage_counts=triage_counts,
                recurrence_counts=recurrence_counts,
                evidence_count=len(artifacts),
                authenticated_findings_count=sum(1 for value in finding_auth_context.values() if value == "authenticated"),
            ),
        }

    def _calculate_risk_score(self) -> float:
        weights = {Severity.CRITICAL: 10.0, Severity.HIGH: 7.0, Severity.MEDIUM: 4.0, Severity.LOW: 1.5, Severity.INFO: 0.0}
        if not self.findings:
            return 0.0
        total = sum(weights.get(f.severity, 0) for f in self.findings)
        normalized = min(10.0, total / max(1, len(self.findings)) * 2)
        return round(normalized, 1)

    def _build_triage_counts(self) -> dict[str, int]:
        counts = {status.value: 0 for status in TriageStatus}
        for finding in self.findings:
            status = self._triage_status_value(finding)
            counts[status] = counts.get(status, 0) + 1
        return counts

    def _build_recurrence_counts(self) -> dict[str, int]:
        recurring = [f for f in self.findings if self._is_recurring(f)]
        return {
            "new_findings_count": len(self.findings) - len(recurring),
            "recurring_findings_count": len(recurring),
            "previously_verified_count": sum(1 for f in self.findings if self._bool_meta(f, "previously_verified")),
            "previously_false_positive_count": sum(1 for f in self.findings if self._bool_meta(f, "previously_marked_false_positive")),
        }

    def _scan_auth_method(self) -> str:
        session = getattr(self.scan, "session", None)
        method = getattr(session, "auth_method", None)
        return getattr(method, "value", None) or "none"

    @staticmethod
    def _finding_confidence(finding: Finding) -> str:
        evidence = finding.evidence or {}
        confidence = evidence.get("confidence") or evidence.get("confidence_level")
        if confidence:
            return str(confidence).lower()
        title = (finding.title or "").lower()
        if title.startswith("api endpoint"):
            return "candidate"
        status = ReportEngine._triage_status_value(finding)
        if status == TriageStatus.VERIFIED.value:
            return "high"
        if status == TriageStatus.FALSE_POSITIVE.value:
            return "none"
        return "medium"

    @staticmethod
    def _build_confidence_counts(finding_confidence: dict[str, str]) -> dict[str, int]:
        counts = {"high": 0, "medium": 0, "low": 0, "candidate": 0, "none": 0}
        for confidence in finding_confidence.values():
            counts[confidence] = counts.get(confidence, 0) + 1
        return counts

    def _build_report_metadata(self) -> dict:
        metadata = dict(self.report_metadata or {})
        started_at = getattr(self.scan, "started_at", None)
        completed_at = getattr(self.scan, "completed_at", None)
        defaults = {
            "report_title": "웹 취약점 점검 결과 보고서",
            "client_name": "",
            "service_name": self.scan.target_url,
            "organization_name": "",
            "author": "",
            "reviewer": "",
            "document_version": "1.0",
            "report_id": str(self.scan.id)[:8],
            "classification": "Internal",
            "assessment_start_date": str(started_at.date()) if started_at else "",
            "assessment_end_date": str(completed_at.date()) if completed_at else "",
            "assessment_scope": "브라우저에서 접근 가능한 웹 리소스 및 API 흐름",
            "out_of_scope": [],
            "methodology": [
                "브라우저 기반 페이지 및 리소스 수집",
                "정적 리소스와 API 흐름 기반 자동 분석",
                "Finding triage 및 evidence artifact 기반 보고서 작성",
            ],
            "limitations": [
                "서버 내부 원본 소스코드는 자동 수집하지 않음",
                "자동 탐지 결과는 검증 필요 후보이며 수동 검증이 필요함",
                "민감정보 원문은 redaction 처리됨",
            ],
            "contact": "",
            "prepared_date": datetime.now(timezone.utc).date().isoformat(),
            "executive_summary_note": "",
            "remediation_due_date": "",
            "custom_notes": "",
        }
        for key, value in defaults.items():
            if key not in metadata or metadata[key] in (None, "", []):
                metadata[key] = value
        return metadata

    def _finding_auth_context(self, finding: Finding, artifacts: list[dict]) -> str:
        if any(artifact.get("auth_context") == "authenticated" for artifact in artifacts):
            return "authenticated"
        evidence_auth = (finding.evidence or {}).get("auth_context")
        if evidence_auth:
            return str(evidence_auth)
        return "authenticated" if self._scan_auth_method() != "none" else "anonymous"

    @staticmethod
    def _finding_verification_required(finding: Finding, artifacts: list[dict]) -> bool:
        if ReportEngine._triage_status_value(finding) == TriageStatus.VERIFIED.value:
            return bool((finding.evidence or {}).get("verification_required", False))
        if ReportEngine._triage_status_value(finding) == TriageStatus.FALSE_POSITIVE.value:
            return False
        return bool((finding.evidence or {}).get("verification_required", True)) or any(
            artifact.get("verification_required") for artifact in artifacts
        )

    @staticmethod
    def _finding_status_phrase(finding: Finding) -> str:
        status = ReportEngine._triage_status_value(finding)
        title = (finding.title or "").lower()
        if status == TriageStatus.VERIFIED.value:
            return "취약점이 확인되었습니다."
        if status == TriageStatus.FALSE_POSITIVE.value:
            return "검토 결과 오탐으로 분류되었습니다."
        if title.startswith("api endpoint"):
            return "추가 권한 검증이 필요한 API 노출 후보입니다."
        return "취약 가능성이 확인되었습니다."

    def _build_kisa_report_metadata(
        self,
        report_metadata: dict,
        triage_counts: dict[str, int],
        recurrence_counts: dict[str, int],
        evidence_count: int,
        authenticated_findings_count: int,
    ) -> dict:
        return {
            "target_url": self.scan.target_url,
            "project_name": getattr(getattr(self.scan, "project", None), "name", "N/A"),
            "scan_id": str(self.scan.id),
            "report_title": report_metadata.get("report_title"),
            "client_name": report_metadata.get("client_name"),
            "service_name": report_metadata.get("service_name"),
            "document_version": report_metadata.get("document_version"),
            "classification": report_metadata.get("classification"),
            "assessment_start_date": report_metadata.get("assessment_start_date"),
            "assessment_end_date": report_metadata.get("assessment_end_date"),
            "scope": report_metadata.get("assessment_scope") or self.scan.target_url,
            "limitations": report_metadata.get("limitations") or [],
            "auth_method": self._scan_auth_method(),
            "verified_findings_count": triage_counts.get("verified", 0),
            "candidate_findings_count": triage_counts.get("candidate", 0),
            "false_positive_count": triage_counts.get("false_positive", 0),
            "recurring_findings_count": recurrence_counts.get("recurring_findings_count", 0),
            "authenticated_findings_count": authenticated_findings_count,
            "evidence_artifacts_count": evidence_count,
            "redaction_applied": True,
        }

    @staticmethod
    def _is_recurring(finding: Finding) -> bool:
        return bool(getattr(finding, "duplicate_of_finding_id", None)) or (getattr(finding, "recurrence_count", 1) or 1) > 1

    @staticmethod
    def _bool_meta(finding: Finding, key: str) -> bool:
        return bool((finding.evidence or {}).get(key))

    @staticmethod
    def _triage_status_value(finding: Finding) -> str:
        return getattr(finding.triage_status, "value", None) or "candidate"

    @staticmethod
    def _risk_level(score: float) -> str:
        if score >= 8.0:
            return "CRITICAL"
        if score >= 6.0:
            return "HIGH"
        if score >= 4.0:
            return "MEDIUM"
        if score >= 2.0:
            return "LOW"
        return "INFORMATIONAL"

    def _build_owasp_mapping(self) -> dict[str, list[Finding]]:
        mapping: dict[str, list[Finding]] = {}
        for f in self.findings:
            cat = f.owasp_category or "Uncategorized"
            mapping.setdefault(cat, []).append(f)
        return mapping

    def _build_kisa_categories(self) -> dict[str, list[Finding]]:
        """Map findings to KISA ISMS-P / KISA vulnerability categories."""
        KISA_MAP = {
            "xss": "입력 데이터 검증 및 표현 (XSS)",
            "sql_injection": "입력 데이터 검증 및 표현 (SQL Injection)",
            "secret_leak": "중요 정보 노출",
            "api_key_exposure": "중요 정보 노출",
            "sensitive_data": "중요 정보 노출",
            "auth_bypass": "인증 및 권한 관리",
            "missing_auth": "인증 및 권한 관리",
            "idor": "접근 통제 미흡",
            "jwt_weakness": "암호화 적용",
            "insecure_storage": "암호화 적용",
            "csrf": "세션 관리",
            "business_logic": "업무 로직 보안",
        }
        categories: dict[str, list[Finding]] = {}
        for f in self.findings:
            cat = KISA_MAP.get(f.vulnerability_type.value, "기타 취약점")
            categories.setdefault(cat, []).append(f)
        return categories

    def _build_executive_summary(self, counts: dict, risk_score: float) -> str:
        total = len(self.findings)
        critical = counts.get("critical", 0)
        high = counts.get("high", 0)
        return (
            f"The security assessment of {self.scan.target_url} identified {total} vulnerabilities "
            f"with an overall risk score of {risk_score}/10 ({self._risk_level(risk_score)}). "
            f"Notably, {critical} critical and {high} high severity issues require immediate attention. "
            "Remediation should prioritize credential exposure and authentication bypass vulnerabilities."
            if total > 0 else
            f"The security assessment of {self.scan.target_url} found no significant vulnerabilities. "
            "The overall risk posture is acceptable, though continued monitoring is recommended."
        )

    @staticmethod
    def _artifact_payload(artifact: FindingEvidenceArtifact) -> dict:
        return {
            "id": str(artifact.id),
            "finding_id": str(artifact.finding_id) if artifact.finding_id else None,
            "artifact_type": artifact.artifact_type.value,
            "title": artifact.title,
            "description": artifact.description,
            "file_path": artifact.file_path,
            "url": artifact.url,
            "http_method": artifact.http_method,
            "status_code": artifact.status_code,
            "content_type": artifact.content_type,
            "content_hash": artifact.content_hash,
            "redacted_body_preview": artifact.redacted_body_preview,
            "line_start": artifact.line_start,
            "line_end": artifact.line_end,
            "storage_type": artifact.storage_type,
            "storage_key": artifact.storage_key,
            "redacted_value": artifact.redacted_value,
            "screenshot_path": artifact.screenshot_path,
            "auth_context": artifact.auth_context,
            "verification_required": artifact.verification_required,
            "metadata": artifact.extra_metadata,
            "created_at": artifact.created_at,
        }

    @staticmethod
    def _build_evidence_summary(artifacts: list[FindingEvidenceArtifact]) -> dict[str, int]:
        return {
            "total_artifacts_count": len(artifacts),
            "screenshot_artifacts_count": sum(1 for a in artifacts if a.artifact_type == EvidenceArtifactType.SCREENSHOT),
            "api_flow_artifacts_count": sum(1 for a in artifacts if a.artifact_type == EvidenceArtifactType.API_FLOW),
            "source_file_artifacts_count": sum(1 for a in artifacts if a.artifact_type == EvidenceArtifactType.SOURCE_FILE),
            "authenticated_artifacts_count": sum(1 for a in artifacts if a.auth_context == "authenticated"),
        }

    @staticmethod
    def _artifacts_by_finding(artifact_index: list[dict]) -> dict[str, list[dict]]:
        grouped: dict[str, list[dict]] = {}
        for artifact in artifact_index:
            finding_id = artifact.get("finding_id")
            if finding_id:
                grouped.setdefault(finding_id, []).append(artifact)
        return grouped

    def _write_json(self, ctx: dict) -> Path:
        output = {
            "scan_id": ctx["scan_id"],
            "target_url": ctx["target_url"],
            "generated_at": ctx["generated_at"],
            "risk_score": ctx["risk_score"],
            "risk_level": ctx["risk_level"],
            "report_metadata": ctx["report_metadata"],
            "scan_policy": ctx["scan_policy"],
            "policy_events": ctx["policy_events"],
            "severity_counts": ctx["severity_counts"],
            "triage_summary": {
                "verified_findings_count": ctx["triage_counts"].get("verified", 0),
                "candidate_findings_count": ctx["triage_counts"].get("candidate", 0),
                "false_positive_count": ctx["triage_counts"].get("false_positive", 0),
                "needs_review_count": ctx["triage_counts"].get("needs_review", 0),
                "fixed_count": ctx["triage_counts"].get("fixed", 0),
                "accepted_risk_count": ctx["triage_counts"].get("accepted_risk", 0),
            },
            "recurrence_summary": ctx["recurrence_counts"],
            "evidence_summary": ctx["evidence_summary"],
            "kisa_report_metadata": ctx["kisa_report_metadata"],
            "executive_summary": ctx["executive_summary"],
            "collection": {
                "page_count": len(ctx["pages"]),
                "resource_count": len(ctx["resources"]),
                "pages": [r.url for r in ctx["pages"]],
                "js_files": [r.url for r in ctx["js_files"]],
                "api_candidates": ctx["api_candidates"],
                "source_maps": [r.url for r in ctx["source_maps"]],
            },
            "findings": [
                {
                    "id": str(f.id),
                    "title": f.title,
                    "severity": f.severity.value,
                    "type": f.vulnerability_type.value,
                    "description": f.description,
                    "affected_url": f.affected_url,
                    "cvss_score": f.cvss_score,
                    "cvss_vector": f.cvss_vector,
                    "cwe_id": f.cwe_id,
                    "owasp_category": f.owasp_category,
                    "recommendation": f.recommendation,
                    "evidence": f.evidence,
                    "code_snippet": f.code_snippet,
                    "poc": f.poc,
                    "reproduction_steps": f.reproduction_steps,
                    "triage_status": self._triage_status_value(f),
                    "analyst_note": f.analyst_note,
                    "verification_note": f.verification_note,
                    "reviewed_at": f.reviewed_at,
                    "reviewed_by": str(f.reviewed_by) if f.reviewed_by else None,
                    "fixed_at": f.fixed_at,
                    "remediation_status": f.remediation_status,
                    "fingerprint": f.fingerprint,
                    "duplicate_of_finding_id": str(f.duplicate_of_finding_id) if f.duplicate_of_finding_id else None,
                    "recurrence_count": f.recurrence_count,
                    "first_seen_at": f.first_seen_at,
                    "last_seen_at": f.last_seen_at,
                    "previous_triage_status": (f.evidence or {}).get("previous_triage_status"),
                    "previous_finding_id": (f.evidence or {}).get("previous_finding_id"),
                    "previously_verified": self._bool_meta(f, "previously_verified"),
                    "previously_marked_false_positive": self._bool_meta(f, "previously_marked_false_positive"),
                    "confidence": ctx["finding_confidence"].get(str(f.id)),
                    "auth_context": ctx["finding_auth_context"].get(str(f.id)),
                    "verification_required": ctx["finding_verification_required"].get(str(f.id)),
                    "status_phrase": ctx["finding_status_phrase"].get(str(f.id)),
                    "artifact_count": len(ctx["artifacts_by_finding"].get(str(f.id), [])),
                    "artifacts": ctx["artifacts_by_finding"].get(str(f.id), []),
                }
                for f in ctx["findings"]
            ],
            "artifacts": ctx["artifact_index"],
            "cross_scan_diff": self._json_cross_scan_diff(ctx["cross_scan_diff"]),
        }
        path = self.output_dir / self.output_filename(ctx["scan_id"], ReportType.FULL, ReportFormat.JSON)
        path.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
        return path

    def _write_markdown(self, ctx: dict, report_type: ReportType) -> Path:
        if report_type == ReportType.KISA:
            return self._write_kisa_markdown(ctx)
        lines = [
            f"# Security Assessment Report",
            f"",
            f"**Target:** {ctx['target_url']}  ",
            f"**Generated:** {ctx['generated_at']}  ",
            f"**Risk Score:** {ctx['risk_score']}/10 ({ctx['risk_level']})  ",
            f"**Auth Method:** {getattr(getattr(ctx['scan'], 'session', None), 'auth_method', 'none')}  ",
            f"**Collected Pages:** {len(ctx['pages'])}  ",
            f"**Collected Resources:** {len(ctx['resources'])}  ",
            f"**Verified Findings:** {ctx['triage_counts'].get('verified', 0)}  ",
            f"**Candidate Findings:** {ctx['triage_counts'].get('candidate', 0)}  ",
            f"**New Findings:** {ctx['recurrence_counts']['new_findings_count']}  ",
            f"**Recurring Findings:** {ctx['recurrence_counts']['recurring_findings_count']}  ",
            f"**Evidence Artifacts:** {ctx['evidence_summary']['total_artifacts_count']}  ",
            f"",
            f"## Report Metadata",
            f"",
            f"**Report Title:** {ctx['report_metadata'].get('report_title') or 'N/A'}  ",
            f"**Client:** {ctx['report_metadata'].get('client_name') or 'N/A'}  ",
            f"**Service:** {ctx['report_metadata'].get('service_name') or 'N/A'}  ",
            f"**Organization:** {ctx['report_metadata'].get('organization_name') or 'N/A'}  ",
            f"**Author:** {ctx['report_metadata'].get('author') or 'N/A'}  ",
            f"**Reviewer:** {ctx['report_metadata'].get('reviewer') or 'N/A'}  ",
            f"**Document Version:** {ctx['report_metadata'].get('document_version') or 'N/A'}  ",
            f"**Classification:** {ctx['report_metadata'].get('classification') or 'N/A'}  ",
            f"**Assessment Period:** {ctx['report_metadata'].get('assessment_start_date') or 'N/A'} - {ctx['report_metadata'].get('assessment_end_date') or 'N/A'}  ",
            f"**Assessment Scope:** {ctx['report_metadata'].get('assessment_scope') or 'N/A'}  ",
            f"",
            f"## Scan Policy Summary",
            f"",
            f"**Intensity:** {ctx['scan_policy'].get('intensity', 'N/A')}  ",
            f"**Max Pages:** {ctx['scan_policy'].get('max_pages', 'N/A')}  ",
            f"**Max Resources:** {ctx['scan_policy'].get('max_resources', 'N/A')}  ",
            f"**Max Depth:** {ctx['scan_policy'].get('max_depth', 'N/A')}  ",
            f"**Max Concurrency:** {ctx['scan_policy'].get('max_concurrency', 'N/A')}  ",
            f"**Request Delay:** {ctx['scan_policy'].get('request_delay_ms', 'N/A')} ms  ",
            f"**Same Origin Only:** {ctx['scan_policy'].get('same_origin_only', 'N/A')}  ",
            f"**Allowed Hosts:** {', '.join(ctx['scan_policy'].get('allowed_hosts') or []) or 'N/A'}  ",
            f"**Excluded Hosts:** {', '.join(ctx['scan_policy'].get('excluded_hosts') or []) or 'N/A'}  ",
            f"**Excluded Paths:** {', '.join(ctx['scan_policy'].get('excluded_paths') or []) or 'N/A'}  ",
            f"**Policy Events:** {len(ctx['policy_events'])}  ",
            f"",
            f"Policy limitations: automated collection is constrained by the saved scan policy. Blocked or skipped URLs are recorded as policy events and are not treated as scan failures.",
            f"",
            *self._markdown_policy_event_lines(ctx["policy_events"]),
            f"",
            f"## Executive Summary",
            f"",
            ctx["executive_summary"],
            f"",
            f"## Severity Summary",
            f"",
            f"| Severity | Count |",
            f"|---|---|",
        ]
        for sev, count in ctx["severity_counts"].items():
            if count > 0:
                lines.append(f"| {sev.upper()} | {count} |")

        lines += [
            "",
            "## Triage Summary",
            "",
            "| Status | Count |",
            "|---|---|",
            f"| Verified | {ctx['triage_counts'].get('verified', 0)} |",
            f"| Candidate | {ctx['triage_counts'].get('candidate', 0)} |",
            f"| Needs Review | {ctx['triage_counts'].get('needs_review', 0)} |",
            f"| False Positive | {ctx['triage_counts'].get('false_positive', 0)} |",
            f"| Accepted Risk | {ctx['triage_counts'].get('accepted_risk', 0)} |",
            f"| Fixed | {ctx['triage_counts'].get('fixed', 0)} |",
        ]

        lines += [
            "",
            "## Recurrence Summary",
            "",
            "| Status | Count |",
            "|---|---|",
            f"| New | {ctx['recurrence_counts']['new_findings_count']} |",
            f"| Recurring | {ctx['recurrence_counts']['recurring_findings_count']} |",
            f"| Previously Verified | {ctx['recurrence_counts']['previously_verified_count']} |",
            f"| Previously False Positive | {ctx['recurrence_counts']['previously_false_positive_count']} |",
        ]

        lines += [
            "",
            "## Evidence Artifact Summary",
            "",
            "| Metric | Count |",
            "|---|---|",
            f"| Total | {ctx['evidence_summary']['total_artifacts_count']} |",
            f"| Screenshots | {ctx['evidence_summary']['screenshot_artifacts_count']} |",
            f"| API flows | {ctx['evidence_summary']['api_flow_artifacts_count']} |",
            f"| Source files | {ctx['evidence_summary']['source_file_artifacts_count']} |",
            f"| Authenticated | {ctx['evidence_summary']['authenticated_artifacts_count']} |",
        ]

        lines += [
            "",
            "## Cross-scan Auth Delta",
            "",
        ]
        diff = ctx["cross_scan_diff"]
        if diff.get("included"):
            lines += [
                f"**Base scan:** {diff['base_scan_id']}  ",
                f"**Compare scan:** {diff['compare_scan_id']}  ",
                f"**Target:** {diff['target_url']}  ",
                f"**Auth methods:** {diff['base_auth_method']} vs {diff['compare_auth_method']}  ",
                "",
                "This section lists authenticated attack surface expansion candidates. It does not confirm authorization bypass; additional validation is required.",
                "",
                f"- New pages: {diff['new_pages_count']}",
                f"- New resources: {diff['new_resources_count']}",
                f"- New API endpoints: {diff['new_api_endpoints_count']}",
                f"- New findings: {diff['new_findings_count']}",
                f"- Verified new findings: {diff.get('verified_new_findings_count', 0)}",
                f"- False-positive new findings: {diff.get('false_positive_new_findings_count', 0)}",
                f"- High confidence new findings: {diff['high_confidence_new_findings_count']}",
                "",
                "### New API Endpoints",
                "",
                *[
                    f"- {item['endpoint']} ({', '.join(item.get('risk_hints', []))}; verification_required={item.get('verification_required', True)})"
                    for item in diff["new_api_endpoints"][:100]
                ],
                "",
                "### New Findings",
                "",
                *[
                    f"- {item['title']} [{item['severity']}/{item['confidence']}; triage={item.get('triage_status', 'candidate')}; recurrence={item.get('recurrence_count', 1)}] {item.get('affected_url') or ''} "
                    f"(verification_required={item.get('verification_required', True)})"
                    for item in diff["new_findings"][:100]
                ],
                "",
                "### Sensitive Endpoint Hints",
                "",
                *[f"- {hint}" for hint in diff["sensitive_endpoint_hints"]],
                "",
            ]
        else:
            lines += ["Cross-scan Auth Delta was not included for this report.", ""]

        lines += [
            "",
            "## Collection Results",
            "",
            "### Pages",
            "",
            *[f"- {r.url} ({r.http_status or 'n/a'})" for r in ctx["pages"][:100]],
            "",
            "### JavaScript Files",
            "",
            *[f"- {r.url}" for r in ctx["js_files"][:100]],
            "",
            "### API Endpoint Candidates",
            "",
            *[f"- {url}" for url in ctx["api_candidates"][:100]],
            "",
            "### Source Maps",
            "",
            *[f"- {r.url}" for r in ctx["source_maps"][:100]],
        ]

        if ctx["verified_findings"]:
            lines += ["", "## Verified Findings", ""]
            for f in ctx["verified_findings"]:
                recurring_note = " recurring" if self._is_recurring(f) else " new"
                lines.append(f"- {f.title} ({f.severity.value.upper()};{recurring_note})")

        lines += ["", "## Security Findings", ""]
        for i, f in enumerate(ctx["security_findings"], 1):
            finding_artifacts = ctx["artifacts_by_finding"].get(str(f.id), [])
            lines += [
                f"### {i}. {f.title}",
                f"",
                f"**Severity:** {f.severity.value.upper()}  ",
                f"**Type:** {f.vulnerability_type.value}  ",
                f"**Triage Status:** {self._triage_status_value(f)}  ",
                f"**Fingerprint:** {f.fingerprint or 'N/A'}  ",
                f"**Recurrence Count:** {f.recurrence_count or 1}  ",
                f"**Previous Triage:** {(f.evidence or {}).get('previous_triage_status') or 'N/A'}  ",
                f"**Previously Verified:** {self._bool_meta(f, 'previously_verified')}  ",
                f"**Previously False Positive:** {self._bool_meta(f, 'previously_marked_false_positive')}  ",
                f"**Evidence Artifacts:** {len(finding_artifacts)}  ",
                f"**CVSS:** {f.cvss_score or 'N/A'}  ",
                f"**CWE:** {f.cwe_id or 'N/A'}  ",
                f"**Reviewed At:** {f.reviewed_at or 'N/A'}  ",
                f"",
                f.description,
                f"",
                f"**Analyst Note:** {f.analyst_note or 'N/A'}  ",
                f"**Verification Note:** {f.verification_note or 'N/A'}  ",
                f"",
                f"**Evidence:**",
                f"",
                "```",
                f.code_snippet or str(f.evidence)[:1000],
                "```",
                f"",
                f"**PoC:**",
                f"",
                "```json",
                json.dumps(f.poc or {}, indent=2, ensure_ascii=False, default=str),
                "```",
                f"",
                f"**Evidence Artifacts:**",
                "",
                *self._markdown_artifact_lines(finding_artifacts[:5]),
                "",
                f"**Reproduction Steps:**",
                *[f"{idx}. {step}" for idx, step in enumerate(f.reproduction_steps or [], 1)],
                f"",
                f"**Recommendation:** {f.recommendation}",
                f"",
                "---",
                "",
            ]

        if ctx["false_positive_findings"]:
            lines += ["", "## False Positives", "", "These findings are separated from active security findings and should not be treated as confirmed vulnerabilities.", ""]
            for f in ctx["false_positive_findings"]:
                lines += [
                    f"### {f.title}",
                    f"**Severity:** {f.severity.value.upper()}  ",
                    f"**Analyst Note:** {f.analyst_note or 'N/A'}  ",
                    f"**Verification Note:** {f.verification_note or 'N/A'}  ",
                    "",
                ]

        if ctx["previously_false_positive_findings"]:
            lines += [
                "",
                "## Previously False Positive Candidates",
                "",
                "These candidate findings matched findings previously marked false positive. They still require analyst verification in this scan.",
                "",
            ]
            for f in ctx["previously_false_positive_findings"]:
                lines.append(f"- {f.title} (previous finding: {(f.evidence or {}).get('previous_finding_id') or 'N/A'})")

        lines += [
            "",
            "## Appendix: Evidence Artifact Index",
            "",
            "| Type | Title | URL / Path | Hash | Auth | Finding |",
            "|---|---|---|---|---|---|",
            *[
                f"| {artifact['artifact_type']} | {artifact['title']} | {artifact.get('url') or artifact.get('file_path') or artifact.get('screenshot_path') or 'N/A'} | {artifact.get('content_hash') or 'N/A'} | {artifact.get('auth_context') or 'N/A'} | {artifact.get('finding_id') or 'N/A'} |"
                for artifact in ctx["artifact_index"][:500]
            ],
        ]

        path = self.output_dir / self.output_filename(ctx["scan_id"], ReportType.FULL, ReportFormat.MARKDOWN)
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _write_kisa_markdown(self, ctx: dict) -> Path:
        lines = [
            "# 웹 취약점 점검 결과 보고서",
            "",
            "## 1. 문서 정보",
            "",
            f"- 보고서 제목: 웹 취약점 점검 결과 보고서",
            f"- 문서 제목: {ctx['report_metadata'].get('report_title') or 'N/A'}",
            f"- 고객사: {ctx['report_metadata'].get('client_name') or 'N/A'}",
            f"- 서비스명: {ctx['report_metadata'].get('service_name') or 'N/A'}",
            f"- 작성자: {ctx['report_metadata'].get('author') or 'N/A'}",
            f"- 검토자: {ctx['report_metadata'].get('reviewer') or 'N/A'}",
            f"- 문서 버전: {ctx['report_metadata'].get('document_version') or 'N/A'}",
            f"- 분류: {ctx['report_metadata'].get('classification') or 'N/A'}",
            f"- 보고서 번호: {ctx['report_metadata'].get('report_id') or 'N/A'}",
            f"- 대상 URL: {ctx['target_url']}",
            f"- 프로젝트명: {ctx['project_name']}",
            f"- 스캔 ID: {ctx['scan_id']}",
            f"- 인증 방식: {ctx['auth_method']}",
            f"- 보고서 생성 일시: {ctx['generated_at']}",
            "- 작성 도구: SSS",
            "",
            "## 2. 진단 개요",
            "",
            "본 보고서는 브라우저에서 접근 가능한 페이지, 정적 리소스, API 흐름, 저장소 상태를 기반으로 자동 수집한 보안 진단 후보를 정리한 문서입니다.",
            f"진단 범위: {ctx['report_metadata'].get('assessment_scope') or 'N/A'}",
            f"제외 범위: {', '.join(ctx['report_metadata'].get('out_of_scope') or []) or 'N/A'}",
            "자동 탐지 결과는 검증 필요 후보이며, 권한 우회 또는 실제 악용 가능성은 별도 수동 검증이 필요합니다.",
            ctx["report_metadata"].get("executive_summary_note") or "",
            "",
            "## 3. Executive Summary",
            "",
            f"- 전체 Finding: {ctx['findings_count']}",
            f"- Verified: {ctx['triage_counts'].get('verified', 0)}",
            f"- Candidate: {ctx['triage_counts'].get('candidate', 0)}",
            f"- False Positive: {ctx['triage_counts'].get('false_positive', 0)}",
            f"- Authenticated Finding: {ctx['authenticated_findings_count']}",
            f"- Recurring Finding: {ctx['recurrence_counts']['recurring_findings_count']}",
            f"- Evidence Artifact: {ctx['evidence_summary']['total_artifacts_count']}",
            f"- Scan Policy: {ctx['scan_policy'].get('intensity', 'N/A')} intensity, max pages {ctx['scan_policy'].get('max_pages', 'N/A')}, max resources {ctx['scan_policy'].get('max_resources', 'N/A')}",
            f"- Policy Events: {len(ctx['policy_events'])}",
            "",
            "## 3-1. Scan Policy Summary",
            "",
            f"- Intensity: {ctx['scan_policy'].get('intensity', 'N/A')}",
            f"- Max pages/resources/depth/concurrency: {ctx['scan_policy'].get('max_pages', 'N/A')} / {ctx['scan_policy'].get('max_resources', 'N/A')} / {ctx['scan_policy'].get('max_depth', 'N/A')} / {ctx['scan_policy'].get('max_concurrency', 'N/A')}",
            f"- Request delay: {ctx['scan_policy'].get('request_delay_ms', 'N/A')} ms",
            f"- Same origin only: {ctx['scan_policy'].get('same_origin_only', 'N/A')}",
            f"- Allowed hosts: {', '.join(ctx['scan_policy'].get('allowed_hosts') or []) or 'N/A'}",
            f"- Excluded hosts: {', '.join(ctx['scan_policy'].get('excluded_hosts') or []) or 'N/A'}",
            f"- Excluded paths: {', '.join(ctx['scan_policy'].get('excluded_paths') or []) or 'N/A'}",
            "자동 수집은 위 정책 범위와 제한 내에서 수행되며, 차단 또는 제외된 URL은 policy event로 기록됩니다.",
            "",
            *self._markdown_policy_event_lines(ctx["policy_events"]),
            "",
            "## 4. 인증 전/후 공격 표면 비교",
            "",
        ]
        diff = ctx["cross_scan_diff"]
        if diff.get("included"):
            lines += [
                "Cross-scan Auth Delta가 포함되었습니다. 이 항목은 로그인 후 새롭게 관찰된 공격 표면 후보이며 권한 우회 확인 결과가 아닙니다.",
                f"- New pages: {diff['new_pages_count']}",
                f"- New resources: {diff['new_resources_count']}",
                f"- New API endpoints: {diff['new_api_endpoints_count']}",
                f"- New findings: {diff['new_findings_count']}",
                "",
            ]
        else:
            lines += ["Cross-scan Auth Delta가 포함되지 않았습니다.", ""]

        lines += [
            "## 5. 취약점 요약표",
            "",
            "| ID | 취약점명 | 유형 | Severity | Confidence | Triage Status | Affected URL | Auth Context | Verification Required |",
            "|---|---|---|---|---|---|---|---|---|",
        ]
        for idx, finding in enumerate(ctx["security_findings"], 1):
            fid = str(finding.id)
            lines.append(
                f"| F-{idx:03d} | {finding.title} | {finding.vulnerability_type.value} | {finding.severity.value} | "
                f"{ctx['finding_confidence'].get(fid)} | {self._triage_status_value(finding)} | {finding.affected_url or 'N/A'} | "
                f"{ctx['finding_auth_context'].get(fid)} | {ctx['finding_verification_required'].get(fid)} |"
            )

        lines += ["", "## 6. 취약점 상세", ""]
        for idx, finding in enumerate(ctx["security_findings"], 1):
            fid = str(finding.id)
            artifacts = ctx["artifacts_by_finding"].get(fid, [])
            lines += [
                f"### F-{idx:03d}. {finding.title}",
                "",
                ctx["finding_status_phrase"].get(fid, "취약 가능성이 확인되었습니다."),
                "",
                f"- 설명: {finding.description}",
                f"- 영향도: {finding.severity.value.upper()} severity로 분류되며 추가 검증 상태는 `{self._triage_status_value(finding)}`입니다.",
                f"- 발생 위치: {finding.affected_url or 'N/A'}",
                f"- Source/Sink: {(finding.evidence or {}).get('source_pattern') or 'N/A'} / {(finding.evidence or {}).get('sink_pattern') or 'N/A'}",
                f"- CWE/OWASP: {finding.cwe_id or 'N/A'} / {finding.owasp_category or 'N/A'}",
                f"- Recurrence: {finding.recurrence_count or 1}",
                "",
                "**증적 요약**",
                "",
                *self._markdown_artifact_lines(artifacts[:5]),
                "",
                "**PoC**",
                "",
                "```json",
                json.dumps(finding.poc or {}, indent=2, ensure_ascii=False, default=str),
                "```",
                "",
                "**재현 절차**",
                "",
                *[f"{step_idx}. {step}" for step_idx, step in enumerate(finding.reproduction_steps or [], 1)],
                "",
                f"**조치 방안:** {finding.recommendation}",
                "",
            ]

        if ctx["false_positive_findings"]:
            lines += ["## False Positive", "", "다음 항목은 검토 결과 오탐으로 분류되어 실제 취약점 조치 대상에서 제외합니다.", ""]
            for finding in ctx["false_positive_findings"]:
                lines.append(f"- {finding.title}: {finding.analyst_note or finding.verification_note or '오탐으로 분류됨'}")

        lines += [
            "",
            "## 7. 증적 첨부",
            "",
            "민감정보 원문은 보고서에 포함하지 않으며 redaction preview, hash, path 중심으로 기록합니다.",
            "",
            "| Type | Title | URL / Path | Hash | Finding |",
            "|---|---|---|---|---|",
            *[
                f"| {artifact['artifact_type']} | {artifact['title']} | {artifact.get('url') or artifact.get('file_path') or artifact.get('screenshot_path') or 'N/A'} | {artifact.get('content_hash') or 'N/A'} | {artifact.get('finding_id') or 'N/A'} |"
                for artifact in ctx["artifact_index"][:500]
            ],
            "",
            "## 8. 조치 우선순위",
            "",
            "Verified high severity, authenticated high confidence, recurring verified finding을 우선 조치합니다. False positive는 조치 대상에서 제외합니다.",
            "",
            "## 9. 한계 및 주의사항",
            "",
            "- 서버 내부 원본 소스코드는 자동 수집하지 않습니다.",
            "- 브라우저에서 접근 가능한 리소스/API 흐름 기반 분석입니다.",
            "- 자동 탐지 결과는 검증 필요 후보입니다.",
            "- API endpoint exposure는 권한 우회 확인이 아니라 점검 후보입니다.",
            "- 민감정보는 redaction 처리됩니다.",
        ]

        path = self.output_dir / self.output_filename(ctx["scan_id"], ReportType.KISA, ReportFormat.MARKDOWN)
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    @staticmethod
    def _markdown_policy_event_lines(policy_events: list[dict]) -> list[str]:
        if not policy_events:
            return ["### Policy Events", "", "No policy events recorded."]
        lines = ["### Policy Events", "", "| Type | Severity | URL | Reason |", "|---|---|---|---|"]
        for event in policy_events[:20]:
            lines.append(
                f"| {event.get('event_type') or 'unknown'} | {event.get('severity') or 'info'} | {event.get('url') or 'N/A'} | {event.get('reason') or 'N/A'} |"
            )
        return lines

    @staticmethod
    def _markdown_artifact_lines(artifacts: list[dict]) -> list[str]:
        if not artifacts:
            return ["No linked artifacts."]
        lines: list[str] = []
        for artifact in artifacts:
            target = artifact.get("url") or artifact.get("file_path") or artifact.get("screenshot_path") or "N/A"
            lines.append(
                f"- `{artifact['artifact_type']}` {artifact['title']} - {target} "
                f"(hash={artifact.get('content_hash') or 'N/A'}, auth={artifact.get('auth_context') or 'N/A'})"
            )
            preview = artifact.get("redacted_body_preview")
            if preview:
                lines.append(f"  Preview: `{str(preview)[:250]}`")
        return lines

    @staticmethod
    def _json_cross_scan_diff(diff: dict) -> dict:
        if not diff.get("included"):
            return {"included": False}
        return {
            "included": True,
            "base_scan_id": diff["base_scan_id"],
            "compare_scan_id": diff["compare_scan_id"],
            "summary": {
                "target_url": diff["target_url"],
                "base_auth_method": diff["base_auth_method"],
                "compare_auth_method": diff["compare_auth_method"],
                "new_pages_count": diff["new_pages_count"],
                "new_resources_count": diff["new_resources_count"],
                "new_api_endpoints_count": diff["new_api_endpoints_count"],
                "new_findings_count": diff["new_findings_count"],
                "high_confidence_new_findings_count": diff["high_confidence_new_findings_count"],
                "verified_new_findings_count": diff.get("verified_new_findings_count", 0),
                "false_positive_new_findings_count": diff.get("false_positive_new_findings_count", 0),
            },
            "new_pages": diff["new_pages"],
            "new_resources": diff["new_resources"],
            "new_api_endpoints": diff["new_api_endpoints"],
            "new_source_maps": diff["new_source_maps"],
            "new_findings": diff["new_findings"],
            "sensitive_endpoint_hints": diff["sensitive_endpoint_hints"],
        }

    def _write_html(self, ctx: dict, report_type: ReportType) -> Path:
        template_name = (
            "report_kisa.html"
            if report_type == ReportType.KISA
            else "report_full.html"
        )
        template = jinja_env.get_template(template_name)
        html = template.render(**ctx)
        path = self.output_dir / self.output_filename(ctx["scan_id"], report_type, ReportFormat.HTML)
        path.write_text(html, encoding="utf-8")
        return path

    def _write_pdf(self, ctx: dict, report_type: ReportType) -> Path:
        self.last_pdf_error = None
        html_path = self._write_html(ctx, report_type)
        pdf_path = html_path.with_suffix(".pdf")
        try:
            import weasyprint
            weasyprint.HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        except Exception as exc:
            self.last_pdf_error = str(exc)
            log.warning("report.pdf_failed_falling_back_to_html", error=str(exc), html_path=str(html_path))
            return html_path
        return pdf_path

    @staticmethod
    def output_filename(scan_id: str, report_type: ReportType, fmt: ReportFormat) -> str:
        short_id = str(scan_id)[:8]
        suffix = "md" if fmt == ReportFormat.MARKDOWN else fmt.value
        return f"sss_report_{short_id}_{report_type.value}.{suffix}"

    @staticmethod
    def pdf_renderer_diagnostic() -> dict:
        try:
            import weasyprint

            with tempfile.TemporaryDirectory() as tmp_dir:
                smoke_path = Path(tmp_dir) / "weasyprint_smoke.pdf"
                weasyprint.HTML(string="<h1>SSS PDF OK</h1><p>한글 테스트</p>").write_pdf(str(smoke_path))
                return {
                    "available": smoke_path.exists() and smoke_path.stat().st_size > 0,
                    "version": getattr(weasyprint, "__version__", "unknown"),
                    "smoke_bytes": smoke_path.stat().st_size if smoke_path.exists() else 0,
                    "error": None,
                }
        except Exception as exc:
            return {"available": False, "version": None, "smoke_bytes": 0, "error": str(exc)}

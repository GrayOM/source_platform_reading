"""Report generation engine.

Supports: PDF, HTML, JSON, Markdown
Formats: KISA, OWASP, Executive Summary, Technical Full
"""
import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import structlog
from jinja2 import Environment, FileSystemLoader, select_autoescape

from app.core.config import get_settings
from app.models.finding import Finding, Severity
from app.models.resource import ResourceType
from app.models.report import ReportFormat, ReportType
from app.models.scan import Scan

settings = get_settings()
log = structlog.get_logger()

TEMPLATES_DIR = Path(__file__).parent / "templates"

jinja_env = Environment(
    loader=FileSystemLoader(str(TEMPLATES_DIR)),
    autoescape=select_autoescape(["html"]),
)


class ReportEngine:
    def __init__(self, scan: Scan, findings: list[Finding], output_dir: Path):
        self.scan = scan
        self.findings = findings
        self.output_dir = output_dir
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def generate(self, fmt: ReportFormat, report_type: ReportType) -> Path:
        context = self._build_context(report_type)

        if fmt == ReportFormat.JSON:
            return self._write_json(context)
        elif fmt == ReportFormat.MARKDOWN:
            return self._write_markdown(context)
        elif fmt == ReportFormat.HTML:
            return self._write_html(context, report_type)
        elif fmt == ReportFormat.PDF:
            return self._write_pdf(context, report_type)
        else:
            raise ValueError(f"Unsupported format: {fmt}")

    def _build_context(self, report_type: ReportType) -> dict:
        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        sorted_findings = sorted(self.findings, key=lambda f: severity_order.get(f.severity, 5))

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

        return {
            "scan": self.scan,
            "target_url": self.scan.target_url,
            "scan_id": str(self.scan.id),
            "report_type": report_type.value,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "findings": sorted_findings,
            "findings_count": len(self.findings),
            "severity_counts": counts,
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
        }

    def _calculate_risk_score(self) -> float:
        weights = {Severity.CRITICAL: 10.0, Severity.HIGH: 7.0, Severity.MEDIUM: 4.0, Severity.LOW: 1.5, Severity.INFO: 0.0}
        if not self.findings:
            return 0.0
        total = sum(weights.get(f.severity, 0) for f in self.findings)
        normalized = min(10.0, total / max(1, len(self.findings)) * 2)
        return round(normalized, 1)

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

    def _write_json(self, ctx: dict) -> Path:
        output = {
            "scan_id": ctx["scan_id"],
            "target_url": ctx["target_url"],
            "generated_at": ctx["generated_at"],
            "risk_score": ctx["risk_score"],
            "risk_level": ctx["risk_level"],
            "severity_counts": ctx["severity_counts"],
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
                }
                for f in ctx["findings"]
            ],
        }
        path = self.output_dir / f"report_{ctx['scan_id'][:8]}.json"
        path.write_text(json.dumps(output, indent=2, default=str), encoding="utf-8")
        return path

    def _write_markdown(self, ctx: dict) -> Path:
        lines = [
            f"# Security Assessment Report",
            f"",
            f"**Target:** {ctx['target_url']}  ",
            f"**Generated:** {ctx['generated_at']}  ",
            f"**Risk Score:** {ctx['risk_score']}/10 ({ctx['risk_level']})  ",
            f"**Auth Method:** {getattr(getattr(ctx['scan'], 'session', None), 'auth_method', 'none')}  ",
            f"**Collected Pages:** {len(ctx['pages'])}  ",
            f"**Collected Resources:** {len(ctx['resources'])}  ",
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

        lines += ["", "## Findings", ""]
        for i, f in enumerate(ctx["findings"], 1):
            lines += [
                f"### {i}. {f.title}",
                f"",
                f"**Severity:** {f.severity.value.upper()}  ",
                f"**Type:** {f.vulnerability_type.value}  ",
                f"**CVSS:** {f.cvss_score or 'N/A'}  ",
                f"**CWE:** {f.cwe_id or 'N/A'}  ",
                f"",
                f.description,
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
                f"**Reproduction Steps:**",
                *[f"{idx}. {step}" for idx, step in enumerate(f.reproduction_steps or [], 1)],
                f"",
                f"**Recommendation:** {f.recommendation}",
                f"",
                "---",
                "",
            ]

        path = self.output_dir / f"report_{ctx['scan_id'][:8]}.md"
        path.write_text("\n".join(lines), encoding="utf-8")
        return path

    def _write_html(self, ctx: dict, report_type: ReportType) -> Path:
        template_name = "report_kisa.html" if report_type == ReportType.KISA else "report_full.html"
        template = jinja_env.get_template(template_name)
        html = template.render(**ctx)
        path = self.output_dir / f"report_{ctx['scan_id'][:8]}_{report_type.value}.html"
        path.write_text(html, encoding="utf-8")
        return path

    def _write_pdf(self, ctx: dict, report_type: ReportType) -> Path:
        html_path = self._write_html(ctx, report_type)
        pdf_path = html_path.with_suffix(".pdf")
        try:
            import weasyprint
            weasyprint.HTML(filename=str(html_path)).write_pdf(str(pdf_path))
        except Exception as exc:
            log.warning("report.pdf_failed_falling_back_to_html", error=str(exc), html_path=str(html_path))
            return html_path
        return pdf_path

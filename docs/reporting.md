# Reporting

SSS report는 자동 수집된 evidence, finding triage, recurrence 정보, scan policy, policy events, report metadata를 함께 저장합니다. 보고서는 분석자가 검토할 수 있는 산출물이며, 자동 탐지 결과를 취약점 확정으로 단정하지 않습니다.

## Report Formats

- `html`: 브라우저에서 확인하기 좋은 전체 보고서입니다.
- `markdown`: PR, 이슈, 운영 문서에 붙이기 좋은 텍스트 보고서입니다.
- `json`: 다른 도구와 연동하기 위한 구조화 데이터입니다.
- `pdf`: WeasyPrint로 HTML report를 PDF 렌더링합니다.

## Report Types

- `full`: finding, triage, recurrence, evidence, API 후보, scan policy, cross-scan diff를 넓게 포함하는 기본 보고서입니다.
- `kisa`: 국내 실무 보고서 흐름에 맞춘 섹션, 문서 메타데이터, 검증 상태, evidence index, 제한 사항을 강조합니다.
- `owasp`: OWASP 관점 분류를 중심으로 정리하는 report type입니다.
- `executive`: 요약과 우선순위 중심 report type입니다.
- `technical`: 기술 상세와 재현/근거 중심 report type입니다.

## PDF Success and Fallback

PDF export는 WeasyPrint가 정상 동작하면 `.pdf` 파일을 생성합니다. PDF 렌더링이 실패하면 report worker는 동일 내용의 HTML report를 생성해 다운로드 가능한 산출물을 남길 수 있습니다. 이 경우 report record의 실제 file extension과 download media type을 확인하세요.

검증 smoke:

```bash
docker compose exec worker python -c "from weasyprint import HTML; HTML(string='<h1>SSS PDF OK</h1><p>한글 테스트</p>').write_pdf('/tmp/sss_pdf_smoke.pdf')"
docker compose exec worker ls -lh /tmp/sss_pdf_smoke.pdf
```

## Report Metadata

UI의 Advanced report metadata 또는 API의 `report_metadata`로 다음 값을 입력할 수 있습니다.

- `report_title`
- `client_name`
- `service_name`
- `organization_name`
- `author`
- `reviewer`
- `document_version`
- `report_id`
- `classification`: `Public`, `Internal`, `Confidential`, `Restricted`
- `assessment_start_date`
- `assessment_end_date`
- `assessment_scope`
- `out_of_scope`
- `methodology`
- `limitations`
- `contact`
- `prepared_date`
- `executive_summary_note`
- `remediation_due_date`
- `custom_notes`

입력하지 않은 값은 report engine의 기본값으로 채워집니다. 예를 들어 기본 limitation에는 서버 내부 원본 소스코드를 자동 수집하지 않는다는 점, 자동 탐지 결과에는 수동 검증이 필요하다는 점, 민감정보 원문은 redaction 처리된다는 점이 포함됩니다.

## Evidence Bundle

완료된 scan은 evidence bundle ZIP으로 내보낼 수 있습니다.

대표 구조:

```text
manifest.json
README.txt
reports/
  full_report.html
  kisa_report.html
  summary.md
  report.json
  report_metadata.json
  scan_policy.json
  policy_events.json
evidence/
  artifact_index.json
  previews/
  screenshots/
```

호환성을 위해 root에도 `kisa_report.html`, `kisa_summary.md`, `artifact_index.json`, `report_metadata.json`, `scan_policy.json`, `policy_events.json`가 포함될 수 있습니다.

## Manifest and Checksums

`manifest.json`에는 다음 정보가 포함됩니다.

- `generated_at`
- `scan_id`
- `target_url`
- `report_type`
- `formats_included`
- `redaction_applied`
- `artifact_count`
- `policy_event_count`
- `screenshot_count`
- `checksums`

`checksums`는 bundle에 포함된 파일별 SHA-256 값입니다. 전달 후 파일 누락이나 변조 여부를 확인할 때 사용합니다.

## Redaction Notice

SSS는 민감정보 원문을 의도적으로 보고서나 preview에 싣지 않습니다. evidence preview는 redacted value, hash, path, context 중심으로 구성됩니다. 문서 예시에도 실제 token, API key, bearer token, JWT 모양의 값을 쓰지 말고 `<REDACTED_TOKEN>` 같은 placeholder를 사용하세요.

## Triage and False Positives

Finding triage 상태:

- `candidate`: 자동 탐지된 검증 후보입니다. 취약점 확정 문구로 해석하지 않습니다.
- `verified`: 분석자가 확인한 항목입니다. 보고서에서 우선 조치 대상으로 강조됩니다.
- `false_positive`: 검토 결과 오탐으로 분류된 항목입니다. 조치 대상과 분리되어 집계됩니다.

False positive는 별도 섹션과 summary count로 분리됩니다. 이전 scan에서 false positive로 표시된 fingerprint가 다시 나타나면 recurrence metadata에 이전 상태가 표시됩니다.

## Verified vs Candidate Wording

보고서 문구는 상태에 따라 달라집니다.

- Verified finding: 취약점이 확인된 것으로 표현합니다.
- Candidate finding: 취약 가능성 또는 추가 권한 검증이 필요한 후보로 표현합니다.
- API endpoint exposure: 권한 우회 확정이 아니라 브라우저 흐름에서 관측된 endpoint 후보로 표현합니다.

## KISA Report Notes

KISA report type은 실무 보고서 작성에 필요한 형태를 빠르게 만들기 위한 템플릿입니다. 공식 제출 양식을 자동 보증하지 않으며, 기관별 양식, 법적 문구, 위험 등급 산정 기준, 수동 검증 결과는 분석자가 검토해야 합니다.

주의사항:

- 자동 수집 범위는 scan policy와 브라우저 접근성에 의해 제한됩니다.
- 서버 내부 원본 소스코드, DB, 내부망 자산은 자동 수집 대상이 아닙니다.
- Candidate는 검증 후보이며, verified와 구분해서 보고해야 합니다.
- Redaction이 적용되므로 원문 증적이 필요한 경우 승인된 별도 보관 절차를 사용하세요.

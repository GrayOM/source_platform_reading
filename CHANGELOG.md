# Changelog

## v1.x

SSS v1.x는 브라우저 접근 가능 리소스/API 흐름 기반 진단, 인증 전후 비교, triage, recurrence, evidence, report export, safety guardrails를 포함하는 1차 완성형 진단 플랫폼 릴리즈입니다.

### Added

- Browser Login scan: 제어된 브라우저 로그인 세션을 캡처해 인증 상태 수집을 지원합니다.
- Cross-scan Diff/Auth Delta: No Auth scan과 Browser Login scan을 비교해 인증 후 새로 보이는 후보를 보고합니다.
- Finding triage: `candidate`, `verified`, `false_positive` 상태와 analyst note를 관리합니다.
- Fingerprint/recurrence tracking: 반복 finding, previously verified, previously false positive 정보를 추적합니다.
- Evidence Artifact: finding별 structured evidence, redacted preview, screenshot, request/response context를 기록합니다.
- KISA report template: 실무 보고서용 섹션, 검증 상태, evidence index, 제한 사항을 포함합니다.
- Report Metadata Builder: 고객사, 서비스명, 작성자, 검토자, 문서 버전, 진단 범위, 제한 사항 등 report metadata를 입력합니다.
- PDF export: WeasyPrint 기반 PDF 생성과 HTML fallback 정책을 지원합니다.
- Evidence bundle export: report, metadata, scan policy, policy events, artifact index, preview, screenshot, manifest/checksum을 ZIP으로 내보냅니다.
- Scan Policy/Safety Guardrails: profile, page/resource/depth/concurrency 제한, request delay/timeout, same-origin, allowed/excluded scope, private target, outside-scope redirect 정책을 적용하고 기록합니다.

### Verification

- Docker Compose config/build 검증
- Backend pytest regression 검증
- Frontend production build 검증
- WeasyPrint PDF smoke 검증
- No Auth, Browser Login, Cross-scan compare, KISA/Full report, evidence bundle E2E 검증
- Scan policy, outside-scope redirect 차단, timeout graceful handling, max concurrency regression 검증
- Secret-like literal grep 검증

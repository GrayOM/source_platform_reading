# Quick Start

이 문서는 SSS를 처음 clone한 뒤 로컬 데모 대상인 vulnerable-site를 스캔하고, 보고서와 evidence bundle을 확인하는 절차입니다.

## 1. Clone

```bash
git clone https://github.com/GrayOM/source_platform_reading.git
cd source_platform_reading
```

## 2. Environment

```bash
cp .env.example .env
```

로컬 데모 기본값은 Docker Compose에 맞춰져 있습니다. 외부 대상이나 운영 배포에서는 `SECRET_KEY`, `FERNET_KEY`, DB password, `SSRF_ALLOWED_HOSTS`, `ALLOW_PRIVATE_TARGETS`를 환경에 맞게 변경하세요.

## 3. Compose Validation and Build

```bash
docker compose config
DOCKER_CONFIG=/tmp/docker-empty-config docker compose build backend worker worker-browser
DOCKER_CONFIG=/tmp/docker-empty-config docker compose build frontend
```

Docker credential helper 관련 오류가 발생하면 위 예시처럼 `DOCKER_CONFIG=/tmp/docker-empty-config`를 붙여 빈 Docker config를 사용합니다.

## 4. Start the Stack and Demo Target

```bash
docker compose --profile e2e up -d
docker compose ps
```

접속 URL:

- SSS Web UI: `http://localhost`
- API docs: `http://localhost/api/docs`
- vulnerable-site host preview: `http://localhost:8081`
- SSS scan target URL: `http://vulnerable-site`

## 5. Sign Up and Log In

1. 브라우저에서 `http://localhost`를 엽니다.
2. 새 계정을 등록합니다.
3. 등록한 계정으로 로그인합니다.

문서나 이슈에 실제 password/token 값을 남기지 마세요.

## 6. Create a Project

1. `Projects`로 이동합니다.
2. 새 프로젝트를 생성합니다.
3. 생성한 프로젝트에서 `New Scan`을 시작합니다.

## 7. Run a No Auth Scan

권장 데모 설정:

- Target URL: `http://vulnerable-site`
- Authentication: `No Auth`
- Max depth: `2` 또는 UI 기본값
- Max pages: `10` 이상
- Analyze source maps: enabled
- Advanced scan policy: `careful`
- Authorization confirmed: checked, 로컬 데모 대상에 한함

스캔 완료 후 `Findings`에서 candidate finding, evidence, code snippet, reproduction steps, recommendation을 확인합니다.

## 8. Run a Browser Login Scan

1. `New Scan`을 다시 시작합니다.
2. 같은 프로젝트와 Target URL `http://vulnerable-site`를 선택합니다.
3. Authentication에서 `Browser Login`을 선택합니다.
4. 스캔 생성 후 제어된 브라우저 로그인 절차를 완료합니다.
5. 스캔이 완료될 때까지 `Scan Detail`에서 progress를 확인합니다.

로컬 fixture의 로그인 페이지는 `/login/`입니다. Browser Login scan은 인증 후 보이는 리소스/API 흐름을 No Auth scan과 비교하는 데 사용됩니다.

## 9. Cross-scan Compare

1. Browser Login scan의 `Reports` 화면으로 이동합니다.
2. `Compare scan`에서 같은 프로젝트와 같은 origin의 No Auth scan을 선택합니다.
3. `full` 또는 `kisa` report를 생성합니다.
4. Cross-scan Auth Delta 섹션에서 인증 후 새로 보이는 후보를 확인합니다.

Cross-scan 결과는 권한 우회 확정이 아닙니다. 인증 후 노출 차이를 정리한 검증 후보입니다.

## 10. Generate Reports

지원 format:

- HTML
- Markdown
- JSON
- PDF

지원 report type:

- `full`
- `kisa`
- `owasp`
- `executive`
- `technical`

PDF는 WeasyPrint 기반으로 렌더링됩니다. 렌더링 실패 시 같은 내용의 HTML report로 fallback될 수 있습니다.

## 11. Download Evidence Bundle

완료된 scan에서 evidence bundle을 생성/다운로드합니다.

Bundle 주요 파일:

- `manifest.json`
- `README.txt`
- `reports/full_report.html`
- `reports/kisa_report.html`
- `reports/summary.md`
- `reports/report.json`
- `reports/report_metadata.json`
- `reports/scan_policy.json`
- `reports/policy_events.json`
- `evidence/artifact_index.json`
- `evidence/previews/`
- `evidence/screenshots/`

`manifest.json`에는 포함 파일의 checksum, artifact 수, policy event 수, redaction 적용 여부가 기록됩니다.

## 12. Stop

```bash
docker compose down
```

데이터까지 초기화하려면:

```bash
docker compose down -v
```

# Developer Verification

이 문서는 v1.x 릴리즈 전 로컬 검증 절차입니다. 기능 추가가 아니라 문서/릴리즈 확인 작업에서도 기존 scan, report, PDF, E2E 동작이 유지되는지 확인합니다.

## Docker Compose

```bash
docker compose config
DOCKER_CONFIG=/tmp/docker-empty-config timeout 300 docker compose build backend worker worker-browser
DOCKER_CONFIG=/tmp/docker-empty-config timeout 300 docker compose build frontend
timeout 300 docker compose --profile e2e up -d --force-recreate backend worker worker-browser vulnerable-site
docker compose ps
```

`DOCKER_CONFIG=/tmp/docker-empty-config`는 Docker credential helper 오류를 피하기 위한 로컬 workaround입니다.

## Backend Tests

```bash
cd backend
.venv/bin/python -m pytest tests/ -v
```

성공 기준:

- 전체 backend pytest가 통과합니다.
- scan policy, report, finding triage, recurrence, PDF fallback, evidence bundle 관련 regression이 깨지지 않습니다.

## Frontend Build

```bash
cd frontend
npm run build
```

성공 기준:

- TypeScript/Vite production build가 완료됩니다.
- Reports, Scan Create, Findings 화면 import/type 문제가 없어야 합니다.

## WeasyPrint PDF Smoke

```bash
docker compose exec worker python -c "from weasyprint import HTML; HTML(string='<h1>SSS PDF OK</h1><p>한글 테스트</p>').write_pdf('/tmp/sss_pdf_smoke.pdf')"
docker compose exec worker ls -lh /tmp/sss_pdf_smoke.pdf
```

성공 기준:

- `/tmp/sss_pdf_smoke.pdf`가 생성됩니다.
- 파일 크기가 0 byte가 아니어야 합니다.
- 한글 텍스트가 포함된 HTML string으로 PDF 렌더링이 실패하지 않아야 합니다.

## Secret-like Grep

문서, 테스트, fixture에 실제 secret pattern처럼 보이는 문자열을 남기지 않습니다.

```bash
git grep -n -E "sk_(test|live)|pk_(test|live)|rk_(test|live)|gh""p_|github""_pat_|A""KIA|A""SIA|xox""b-|xox""p-|Bearer e""yJ"
```

성공 기준:

- 출력이 없어야 합니다.
- 필요한 예시는 `<REDACTED_TOKEN>` 또는 문자열 분리 표현을 사용합니다.

## E2E Fixture

로컬 vulnerable-site는 Docker Compose `e2e` profile로 실행됩니다.

```bash
docker compose --profile e2e up -d vulnerable-site
```

접속:

- SSS scan target: `http://vulnerable-site`
- Host preview: `http://localhost:8081`

주요 route:

- `/login/`: Browser Login scan용 로그인 fixture입니다.
- `/outside-link/`: outside-scope link 차단 확인용 fixture입니다.
- `/mixed-scope/`: same-origin link와 outside-scope link가 섞인 fixture입니다.
- `/redirect-outside`: outside-scope redirect 차단 확인용 fixture입니다.

## Manual Demo Success Criteria

- 회원가입/로그인이 동작합니다.
- 프로젝트 생성이 동작합니다.
- `http://vulnerable-site` No Auth scan이 completed 상태가 됩니다.
- Browser Login scan이 completed 상태가 됩니다.
- Cross-scan compare report가 생성됩니다.
- KISA report와 Full report가 다운로드됩니다.
- PDF export 또는 HTML fallback이 정상적으로 파일을 남깁니다.
- Evidence bundle ZIP이 생성되고 `manifest.json`, `reports/`, `evidence/artifact_index.json`가 포함됩니다.
- outside-scope fixture scan에서 redirect/link 차단 event가 `policy_events`에 기록됩니다.

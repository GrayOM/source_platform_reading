# SSS Platform - Smart Security Scanner

[![CI](https://github.com/GrayOM/source_platform_reading/actions/workflows/ci.yml/badge.svg)](https://github.com/GrayOM/source_platform_reading/actions/workflows/ci.yml)

SSS Platform은 브라우저에서 접근 가능한 웹 리소스와 API 흐름을 수집하고, 자동 분석 결과를 triage와 evidence 중심 보고서로 정리하는 Dockerized 웹 보안 진단 플랫폼입니다. URL 기반 No Auth scan, Browser Login scan, Cross-scan Auth Delta 비교, finding triage, fingerprint/recurrence tracking, evidence artifact, KISA/Full/Markdown/JSON/PDF report, evidence bundle export를 지원합니다.

SSS는 서버 내부 원본 소스코드를 가져오는 도구가 아닙니다. Playwright 브라우저가 접근할 수 있는 페이지, JavaScript, source map, XHR/fetch 흐름, storage 사용, 응답 메타데이터와 같은 클라이언트 관측 가능 자료를 바탕으로 분석합니다.

선택 AI 고도화는 NVIDIA NIM과 Anthropic을 지원합니다. NVIDIA 설정이 있으면 `deepseek-ai/deepseek-v4-pro`로 인증/인가와 비즈니스 로직 보조 분석을 수행하고, `nvidia/gliner-pii`로 수집 리소스의 PII 노출 후보를 찾습니다. 임베딩과 rerank adapter도 준비되어 있어 이후 RAG/근거 우선순위화에 사용할 수 있습니다.

> 허가받은 대상에만 사용하세요. SSS는 무차별 요청, 공격 자동화, exploit 실행, credential stuffing, brute force, fuzzing 도구가 아닙니다.

## 주요 기능

- URL 기반 scan: 공개 페이지와 브라우저에서 관측 가능한 리소스/API 흐름을 수집합니다.
- Browser Login scan: 제어된 브라우저 로그인 세션을 캡처한 뒤 인증 상태에서 크롤링합니다.
- Cross-scan Auth Delta: No Auth scan과 Browser Login scan을 비교해 인증 후 새로 보이는 attack surface 후보를 정리합니다.
- Finding triage: `candidate`, `verified`, `false_positive` 상태와 analyst note를 관리합니다.
- Fingerprint/recurrence tracking: 같은 프로젝트 내 반복 finding을 fingerprint로 연결하고 이전 verified/false positive 상태를 표시합니다.
- Evidence Artifact: finding별 근거, redacted preview, screenshot, request/response context를 구조화합니다.
- Report export: Full, KISA, OWASP, Executive, Technical report type과 HTML, Markdown, JSON, PDF format을 지원합니다.
- Evidence bundle: 보고서, artifact index, redacted preview, screenshot, manifest, checksum을 ZIP으로 묶어 내보냅니다.
- Report Metadata Builder: 고객사, 서비스명, 작성자, 진단 범위, 제한 사항, 문서 분류 등 실무 보고서 필드를 입력합니다.
- Scan Policy/Safety Guardrails: low/normal/careful profile, page/resource/depth/concurrency 제한, same-origin, allowed/excluded host/path, private target, outside-scope redirect 정책을 기록합니다.
- NVIDIA AI adapters: chat/completions, GLiNER PII, text/code embeddings, retrieval reranking 호출 방식을 분리해 모델별 API 차이를 흡수합니다.
- PII exposure candidate: `nvidia/gliner-pii`가 감지한 개인정보 후보를 redacted evidence로 저장합니다.

## 안전 범위

- 소유하거나 명시적으로 허가받은 시스템만 스캔하세요.
- 자동 탐지 결과는 검증 후보입니다. 특히 API endpoint exposure는 권한 우회 확정이 아니라 추가 검증이 필요한 노출 후보입니다.
- `candidate` finding은 triage가 필요하며, `verified`만 분석자가 확인한 항목으로 취급하세요.
- `false_positive`는 보고서에서 분리되어 조치 대상과 구분됩니다.
- private target은 기본적으로 차단됩니다. 로컬 E2E/dev 대상은 `SSRF_ALLOWED_HOSTS`로 명시된 host만 허용하는 구성을 사용합니다.
- outside-scope link/redirect, excluded host/path, max limit 도달, timeout 등은 `policy_events`로 남고 보고서와 evidence bundle에 포함됩니다.
- 문서와 테스트 데이터에는 실제 secret-like literal을 넣지 마세요. 예시는 `<REDACTED_TOKEN>`처럼 표현합니다.

## Architecture

```text
Browser UI
  |
  v
Nginx reverse proxy
  |
  +-- FastAPI backend
  |     +-- PostgreSQL
  |     +-- Redis
  |
  +-- Celery worker
  |     +-- analysis / reports
  |
  +-- Celery worker-browser
        +-- Playwright crawler
```

주요 구성:

- `backend`: FastAPI, SQLAlchemy, Alembic, Celery
- `frontend`: React, Vite, React Query, Axios
- `worker-browser`: Playwright 기반 크롤링, browser login, resource/API collection
- `worker`: 분석, report generation, evidence bundle generation
- `postgres`: 프로젝트, 스캔, finding, artifact, report 메타데이터 저장
- `redis`: Celery broker/result backend 및 progress pub/sub
- `nginx`: frontend/API/WebSocket reverse proxy

## Requirements

- Docker 24+
- Docker Compose v2+
- Node.js 20+ and Python 3.12+ for local development

AI API key는 선택 사항입니다. API key가 없거나 placeholder이면 deterministic analyzer와 보고서 생성은 계속 동작하고, AI 기반 보조 분석만 건너뜁니다.

NVIDIA NIM을 사용할 때는 `.env`에 최소한 아래 값을 설정합니다. 모델별 키가 다르면 adapter-specific key를 채우고, 비워두면 `NVIDIA_API_KEY`를 재사용합니다.

```bash
AI_PROVIDER=auto
NVIDIA_API_KEY=<your_nvidia_api_key>
NVIDIA_NIM_MODEL=deepseek-ai/deepseek-v4-pro
NVIDIA_PII_MODEL=nvidia/gliner-pii
NVIDIA_EMBED_MODEL=nvidia/nv-embed-v1
NVIDIA_CODE_EMBED_MODEL=nvidia/nv-embedcode-7b-v1
NVIDIA_RERANK_URL=https://ai.api.nvidia.com/v1/retrieval/nvidia/reranking
NVIDIA_RERANK_MODEL=nv-rerank-qa-mistral-4b:1
```

## Quick Start

전체 절차는 [docs/quickstart.md](docs/quickstart.md)에 정리되어 있습니다.

```bash
git clone https://github.com/GrayOM/source_platform_reading.git
cd source_platform_reading
cp .env.example .env
docker compose config
DOCKER_CONFIG=/tmp/docker-empty-config docker compose build backend worker worker-browser
DOCKER_CONFIG=/tmp/docker-empty-config docker compose build frontend
docker compose --profile e2e up -d
docker compose ps
```

Docker credential helper 오류가 나면 `DOCKER_CONFIG=/tmp/docker-empty-config`를 붙여 빌드하세요.

접속:

- Web UI: `http://localhost`
- Swagger UI: `http://localhost/api/docs`
- ReDoc: `http://localhost/api/redoc`
- Demo vulnerable-site from host browser: `http://localhost:8081`
- Demo target URL from SSS container network: `http://vulnerable-site`

기본 데모 흐름:

1. `http://localhost` 접속
2. 회원가입 후 로그인
3. 프로젝트 생성
4. Target URL `http://vulnerable-site`로 No Auth scan 실행
5. Browser Login scan 실행
6. Cross-scan compare 대상 선택 후 report 생성
7. HTML/KISA/PDF/Markdown/JSON report 다운로드
8. Evidence bundle 다운로드 후 `manifest.json`, `reports/`, `evidence/` 확인

## Local Demo Model

SSS is designed to be run as a local demo or controlled internal tool. Start it only when testing or demonstrating the platform, then stop the containers when finished.

기본 실행:

```bash
docker compose --profile e2e up -d
```

종료:

```bash
docker compose down
```

데이터까지 초기화하고 싶을 때:

```bash
docker compose down -v
```

GitHub Releases are used to mark stable versions of SSS. They do not host the running backend, workers, database, or Redis services.

For an always-on deployment, SSS must run on a VPS or cloud server with Docker Compose or another container runtime. For portfolio and demo purposes, the recommended mode is local demo execution.

Do not expose SSS as a public scanner unless authentication, authorization, abuse controls, rate limits, quotas, and audit logging are properly configured. Use it only on systems you own or are explicitly authorized to assess.

## Screenshots

로컬 데모 실행 후 주요 사용 흐름과 결과 화면은 아래와 같습니다.

**1. Dashboard**

스캔 수, finding 수, 최근 스캔 상태를 빠르게 확인합니다.

![SSS dashboard](docs/screenshots/dashboard.png)

**2. Scan Create**

대상 URL, 인증 방식, scan policy, crawl limit, source map 분석 여부를 설정합니다.

![Scan creation](docs/screenshots/scan-create.png)

**3. Scan Detail**

진행률, policy event, evidence artifact, cross-scan diff candidate를 확인합니다.

![Scan detail](docs/screenshots/scan-detail.png)

**4. Finding Detail**

finding 설명, severity, evidence, reproduction steps, triage 상태를 검토합니다. NVIDIA PII adapter가 켜진 경우 PII 후보는 redacted evidence로 표시됩니다.

![Finding detail](docs/screenshots/finding-detail.png)

**5. Reports**

Full/KISA/Markdown/JSON/PDF 보고서와 evidence bundle을 생성하고 다운로드합니다.

![Reports](docs/screenshots/reports.png)

## Documentation

- [Quick Start](docs/quickstart.md): clone부터 demo scan, report, evidence bundle 확인까지의 실행 절차
- [Reporting](docs/reporting.md): report type/format, PDF fallback, metadata, evidence bundle, redaction, verified/candidate 문구
- [Scan Policy](docs/scan-policy.md): safety profile, limits, scope controls, private target, redirect outside-scope, policy events
- [Developer Verification](docs/verification.md): Docker build, E2E fixture, backend pytest, frontend build, WeasyPrint smoke, secret-like grep
- [Release Checklist](docs/release-checklist.md): v1.x release freeze, verification, manual demo, and publish checklist
- [Architecture](docs/architecture.md): 시스템 구성과 데이터 흐름

## E2E Vulnerable Site

로컬 데모와 회귀 검증을 위해 의도적으로 취약한 테스트 타겟을 제공합니다.

```bash
docker compose --profile e2e up -d vulnerable-site
```

테스트 URL:

- SSS scan target: `http://vulnerable-site`
- Host browser preview: `http://localhost:8081`

주요 route:

- `/login/`: Browser Login scan용 로그인 fixture
- `/outside-link/`: outside-scope link 차단 확인
- `/mixed-scope/`: same-origin과 outside-scope link 혼합 fixture
- `/redirect-outside`: outside-scope redirect 차단 확인

## API Overview

```text
POST   /api/v1/auth/register
POST   /api/v1/auth/login
POST   /api/v1/auth/refresh

GET    /api/v1/projects
POST   /api/v1/projects

GET    /api/v1/scans
POST   /api/v1/scans
GET    /api/v1/scans/{scan_id}
POST   /api/v1/scans/{scan_id}/cancel
POST   /api/v1/scans/{scan_id}/browser-auth/start
GET    /api/v1/scans/{scan_id}/diff-candidates

GET    /api/v1/findings
PATCH  /api/v1/findings/{finding_id}

GET    /api/v1/reports/scans/{scan_id}
POST   /api/v1/reports/scans/{scan_id}/generate
POST   /api/v1/reports/scans/{scan_id}/evidence-bundle
GET    /api/v1/reports/{report_id}/download

WS     /ws/scans/{scan_id}?token=<REDACTED_TOKEN>
```

## Local Development

```bash
make setup
make dev
make test
make lint
```

직접 검증:

```bash
cd backend
.venv/bin/python -m pytest tests/ -v

cd ../frontend
npm run build
```

릴리즈 검증 절차는 [docs/verification.md](docs/verification.md)를 기준으로 실행하세요.

## Environment

| 변수 | 기본값 / 예시 | 설명 |
|---|---|---|
| `POSTGRES_USER` | `sss` | PostgreSQL 사용자 |
| `POSTGRES_PASSWORD` | dev 기본값 | PostgreSQL 비밀번호 |
| `POSTGRES_DB` | `sss_platform` | 기본 DB |
| `SECRET_KEY` | dev 기본값 | JWT 서명 키 |
| `FERNET_KEY` | dev 기본값 | 세션 데이터 암호화 키 |
| `ENVIRONMENT` | `development` | 실행 환경 |
| `SCAN_DATA_PATH` | `/data/scans` | 수집 리소스와 보고서 저장 경로 |
| `SSRF_ALLOWED_HOSTS` | `vulnerable-site,host.docker.internal` | development/e2e/test에서 허용되는 테스트 host |
| `ALLOW_PRIVATE_TARGETS` | `false` | private target 허용 여부 |
| `AI_PROVIDER` | `auto` | `auto`, `nvidia`, `anthropic` 중 선택 |
| `NVIDIA_API_KEY` | empty | NVIDIA NIM 공통 API key |
| `NVIDIA_NIM_MODEL` | `deepseek-ai/deepseek-v4-pro` | chat/completions 기반 보조 분석 모델 |
| `NVIDIA_PII_MODEL` | `nvidia/gliner-pii` | PII 탐지 모델 |
| `NVIDIA_EMBED_MODEL` | `nvidia/nv-embed-v1` | 문서/RAG용 embedding 모델 |
| `NVIDIA_CODE_EMBED_MODEL` | `nvidia/nv-embedcode-7b-v1` | 코드 embedding 모델 |
| `NVIDIA_RERANK_URL` | NVIDIA retrieval reranking URL | rerank 전용 endpoint |
| `NVIDIA_RERANK_MODEL` | `nv-rerank-qa-mistral-4b:1` | retrieval rerank 모델 |
| `ANTHROPIC_API_KEY` | empty | 선택 AI 분석 키 |

운영 또는 외부 대상 테스트에서는 `SECRET_KEY`, `FERNET_KEY`, DB password, 허용 host, private target 정책을 반드시 환경에 맞게 변경하세요.

## Project Structure

```text
.
├── backend/
│   ├── alembic/
│   ├── app/
│   │   ├── api/v1/
│   │   ├── core/
│   │   ├── models/
│   │   ├── schemas/
│   │   ├── services/
│   │   └── workers/
│   └── tests/
├── docs/
├── e2e/vulnerable-site/
├── frontend/src/
├── infra/nginx/
├── docker-compose.yml
└── README.md
```

## Troubleshooting

Docker credential helper 오류:

```bash
DOCKER_CONFIG=/tmp/docker-empty-config docker compose build backend worker worker-browser
DOCKER_CONFIG=/tmp/docker-empty-config docker compose build frontend
```

기존 Postgres volume password mismatch:

```bash
docker compose down -v
docker compose --profile e2e up -d
```

로그 확인:

```bash
docker compose logs --tail=100 backend
docker compose logs --tail=100 worker
docker compose logs --tail=100 worker-browser
```

## License and Responsible Use

Use this project only on systems you own or have explicit permission to test. SSS collects and analyzes browser-accessible resources and API flows; it is not intended for unauthorized scanning or exploitation.

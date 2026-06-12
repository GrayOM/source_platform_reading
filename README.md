# SSS Platform — Smart Security Scanner

AI 기반 웹 애플리케이션 보안 취약점 분석 플랫폼.  
대상 URL을 입력하면 인증된 크롤링 → 클라이언트 리소스 수집 → 멀티 에이전트 AI 분석 → 전문 보고서 생성까지 자동으로 수행합니다.

---

## 목차

1. [요구사항](#요구사항)
2. [빠른 시작 (Docker)](#빠른-시작-docker)
3. [로컬 개발 환경 설정](#로컬-개발-환경-설정)
4. [환경변수 설명](#환경변수-설명)
5. [사용 방법](#사용-방법)
6. [AI 분석 에이전트](#ai-분석-에이전트)
7. [보고서 출력 형식](#보고서-출력-형식)
8. [API 문서](#api-문서)
9. [테스트](#테스트)
10. [문제 해결](#문제-해결)

---

## 요구사항

| 항목 | 버전 |
|---|---|
| Docker | 24.0 이상 |
| Docker Compose | v2.20 이상 |
| Anthropic API Key | [console.anthropic.com](https://console.anthropic.com) 에서 발급 |

> 로컬 개발 시 추가로 Python 3.12+, Node.js 20+ 필요

---

## 빠른 시작 (Docker)

### 1. 저장소 복제

```bash
git clone <repo-url> sss-platform
cd sss-platform
```

### 2. 환경변수 파일 생성

```bash
cp .env.example .env
```

`.env` 파일을 열어 아래 필수 항목을 채웁니다.

```env
# 필수 — 강력한 랜덤 값으로 변경
POSTGRES_PASSWORD=my_strong_db_password

# 필수 — 32자 이상 랜덤 문자열
SECRET_KEY=my_super_secret_key_change_this_now

# 필수 — Fernet 키 생성 방법:
#   python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
FERNET_KEY=your_generated_fernet_key_here=

# 필수 — Anthropic API 키
ANTHROPIC_API_KEY=sk-ant-...
```

### 3. Fernet 키 생성 (처음 한 번)

```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

출력된 값을 `.env`의 `FERNET_KEY`에 붙여넣습니다.

### 4. 서비스 시작

```bash
docker compose build
docker compose up -d
```

> 첫 빌드는 Playwright 브라우저 다운로드 때문에 5~10분 소요됩니다.

### 5. 접속

| 서비스 | 주소 |
|---|---|
| 웹 UI | http://localhost |
| API 문서 (Swagger) | http://localhost/api/docs |
| API 문서 (ReDoc) | http://localhost/api/redoc |

### 6. 서비스 중지

```bash
docker compose down          # 컨테이너만 중지 (데이터 유지)
docker compose down -v       # 컨테이너 + 볼륨 전체 삭제
```

---

## 로컬 개발 환경 설정

Docker 없이 백엔드·프론트엔드를 직접 실행할 때 사용합니다.

### 한 번에 설정

```bash
make setup
```

내부적으로 다음을 실행합니다.
- Python 가상환경 생성 및 패키지 설치
- Playwright Chromium 브라우저 설치
- Node.js 패키지 설치
- `.env.example` → `.env` 복사

### DB·Redis만 Docker로 실행하고 앱은 로컬 실행

```bash
# 터미널 1: 인프라 (DB, Redis)
docker compose up postgres redis -d

# 터미널 2: 백엔드 API 서버
cd backend
source .venv/bin/activate    # Windows: .venv\Scripts\activate
uvicorn app.main:app --reload --port 8000

# 터미널 3: 크롤/인증 워커 (Playwright 필요)
cd backend
source .venv/bin/activate
celery -A app.core.celery_app worker -Q crawl,auth -c 1 --loglevel=info

# 터미널 4: 분석/보고서 워커
cd backend
source .venv/bin/activate
celery -A app.core.celery_app worker -Q default,analysis,reports -c 4 --loglevel=info

# 터미널 5: 프론트엔드 개발 서버
cd frontend
npm run dev     # http://localhost:3000
```

### 데이터베이스 마이그레이션

```bash
cd backend
alembic upgrade head
```

---

## 환경변수 설명

| 변수 | 필수 | 설명 |
|---|---|---|
| `POSTGRES_PASSWORD` | ✅ | PostgreSQL 비밀번호 |
| `SECRET_KEY` | ✅ | JWT 서명 키 (32자 이상) |
| `FERNET_KEY` | ✅ | 세션 쿠키 암호화 키 (Fernet 형식) |
| `ANTHROPIC_API_KEY` | ✅ | AI 분석에 사용하는 Claude API 키 |
| `GEMINI_API_KEY` | ❌ | 보조 AI 백엔드 (선택) |
| `MAX_CRAWL_DEPTH` | ❌ | 크롤 최대 깊이 (기본값: 5) |
| `MAX_CRAWL_PAGES` | ❌ | 크롤 최대 페이지 수 (기본값: 500) |
| `CRAWL_CONCURRENCY` | ❌ | 동시 크롤 페이지 수 (기본값: 5) |
| `MAX_RESOURCE_SIZE_MB` | ❌ | 파일 1개 최대 크기 MB (기본값: 10) |
| `SCAN_DATA_PATH` | ❌ | 수집 리소스 저장 경로 (기본값: /data/scans) |

---

## 사용 방법

### 1단계: 회원가입 / 로그인

http://localhost 접속 후 계정을 생성합니다.

### 2단계: 프로젝트 생성

좌측 메뉴 **Projects** → **New Project** 버튼 클릭 → 프로젝트 이름 입력 후 생성.

프로젝트는 여러 스캔을 묶는 단위입니다 (예: "고객사 A 정기 점검").

### 3단계: 스캔 생성

대시보드의 **New Scan** 버튼을 클릭하면 4단계 마법사가 시작됩니다.

#### Step 1 — 대상 URL

```
프로젝트 선택 후 대상 URL 입력
예: https://target.example.com
```

- `http://` 또는 `https://` 로 시작해야 합니다.
- 사설 IP(10.x, 192.168.x, localhost)는 SSRF 보호로 차단됩니다.

#### Step 2 — 인증 방식 선택

| 방식 | 사용 시기 |
|---|---|
| **No Auth** | 공개 사이트 |
| **Browser Login** | 직접 로그인이 필요한 사이트 (MFA, SSO 포함) |
| **Paste Cookies** | 브라우저 DevTools 또는 Burp Suite에서 쿠키 내보내기 가능한 경우 |
| **Bearer Token** | API 토큰 또는 JWT로 인증하는 경우 |

**Browser Login 흐름:**
1. 스캔 시작 시 실제 Chromium 브라우저 창이 열립니다.
2. 대상 사이트에 직접 로그인합니다 (MFA 입력 포함).
3. 로그인 완료 후 브라우저 하단의 초록색 **"✓ Done — Submit to SSS"** 버튼을 클릭합니다.
4. 세션이 캡처되어 암호화 저장되고 크롤러에 자동 주입됩니다.

**Paste Cookies 형식 (JSON 배열):**
```json
[
  {
    "name": "session_id",
    "value": "abc123xyz",
    "domain": "example.com",
    "path": "/",
    "secure": true,
    "httpOnly": true
  }
]
```
> Chrome DevTools → Application → Cookies → 우클릭 → Copy all as JSON 으로 쉽게 복사할 수 있습니다.

#### Step 3 — 크롤 설정

| 옵션 | 설명 | 권장값 |
|---|---|---|
| Max Depth | 링크 추적 최대 깊이 | 중형 사이트: 4~5 |
| Max Pages | 크롤 최대 페이지 수 | 500~1000 |
| Excluded Paths | 제외할 경로 (한 줄에 하나) | `/logout`, `/cdn` |
| Follow Subdomains | 서브도메인 포함 여부 | 범위 확인 후 설정 |
| Screenshot Pages | 페이지 스크린샷 저장 | 보고서용이면 활성화 |
| Analyze Source Maps | `.map` 파일 분석 | 권장 활성화 |

#### Step 4 — 검토 후 시작

설정 확인 후 **Start Scan** 클릭.

### 4단계: 실시간 진행 모니터링

스캔 상세 페이지에서 WebSocket을 통해 실시간으로 진행 상황을 확인합니다.

```
Pending → Authenticating → Crawling → Analyzing → Completed
```

| 지표 | 설명 |
|---|---|
| Pages | 크롤된 페이지 수 |
| Resources | 수집된 파일 수 (JS, CSS, JSON 등) |
| Findings | 발견된 취약점 수 |

### 5단계: 취약점 확인

스캔 완료 후 **View Findings** 버튼 클릭.

- 심각도별 필터 (Critical / High / Medium / Low / Info)
- 각 항목 클릭 시 상세 정보 확인:
  - CWE 번호, CVSS 점수
  - 영향 URL 및 파라미터
  - 증거 코드 스니펫
  - 조치 방안
- 상태 변경: `New → Confirmed / False Positive / Out of Scope / Accepted`

### 6단계: 보고서 생성

**Generate Report** 버튼 클릭 후 형식과 유형 선택.

**보고서 형식:**
- `PDF` — 인쇄용 전문 보고서
- `HTML` — 웹 브라우저에서 열리는 보고서
- `JSON` — 다른 도구와의 연동용
- `Markdown` — Git 저장소에 첨부용

**보고서 유형:**
- `Full Report` — 전체 기술 보고서
- `KISA Format` — 한국인터넷진흥원(KISA) 양식, 한국어
- `OWASP Top 10` — OWASP Top 10 항목별 매핑
- `Executive Summary` — 경영진용 요약본
- `Technical Details` — 기술 상세 보고서

생성 완료 후 **Download** 버튼으로 파일을 저장합니다.

---

## AI 분석 에이전트

스캔은 6개 전문 에이전트가 2라운드로 분석합니다.

### Round 1 — 병렬 실행

| 에이전트 | 탐지 항목 |
|---|---|
| **JS Analyzer** | DOM XSS, 프로토타입 오염, 위험한 eval(), 안전하지 않은 postMessage |
| **Secret Detector** | AWS/GCP/GitHub API 키, JWT 토큰, DB 연결 문자열, PEM 키 등 16가지 패턴 |
| **API Mapper** | XHR/Fetch 엔드포인트, JS 소스 내 API 경로, Swagger/OpenAPI 노출 여부 |

### Round 2 — 순차 실행 (Round 1 결과 참조)

| 에이전트 | 탐지 항목 |
|---|---|
| **Auth Analyzer** | JWT 취약점, IDOR, CSRF, OAuth 설정 오류, 인증 우회 |
| **Business Logic** | 가격 조작, 워크플로우 우회, 경쟁 조건, 매개변수 변조 |

---

## 보고서 출력 형식

### KISA 형식 (한국어)

한국인터넷진흥원 웹 취약점 점검 기준에 맞춘 보고서입니다.

- 심각도: 심각 / 높음 / 보통 / 낮음 / 정보
- KISA ISMS-P 항목 매핑
- 한국어 조치 방안 포함
- PDF 인쇄 최적화

### OWASP 형식

OWASP Top 10:2021 카테고리별 분류 보고서입니다.

- A01:2021 ~ A10:2021 매핑
- CVSS 3.1 점수
- CWE 번호

---

## API 문서

서비스 실행 후 아래 URL에서 전체 API 명세를 확인할 수 있습니다.

- **Swagger UI**: http://localhost/api/docs
- **ReDoc**: http://localhost/api/redoc
- **OpenAPI JSON**: http://localhost/api/openapi.json

### 주요 엔드포인트 요약

```
POST   /api/v1/auth/register          회원가입
POST   /api/v1/auth/login             로그인 (JWT 발급)
POST   /api/v1/auth/refresh           토큰 갱신

GET    /api/v1/projects               프로젝트 목록
POST   /api/v1/projects               프로젝트 생성

POST   /api/v1/scans                  스캔 생성 및 시작
GET    /api/v1/scans/{id}             스캔 상세 조회
POST   /api/v1/scans/{id}/cancel      스캔 중단
POST   /api/v1/scans/{id}/browser-auth/start   브라우저 인증 시작

GET    /api/v1/findings               취약점 목록 (필터: scan_id, severity)
PATCH  /api/v1/findings/{id}          취약점 상태/메모 수정

POST   /api/v1/reports/scans/{id}/generate   보고서 생성 요청
GET    /api/v1/reports/{id}/download         보고서 파일 다운로드

WS     /ws/scans/{id}?token=<jwt>     실시간 진행 상황 스트림
```

---

## 테스트

```bash
# 전체 테스트 실행
make test

# 커버리지 포함
cd backend && python -m pytest tests/ -v --cov=app --cov-report=html

# 특정 파일만
cd backend && python -m pytest tests/test_secret_detector.py -v

# 특정 테스트만
cd backend && python -m pytest tests/test_security_utils.py::test_ssrf_validation_blocks_localhost -v
```

---

## 문제 해결

### 서비스 로그 확인

```bash
docker compose logs backend        # API 서버 로그
docker compose logs worker         # 분석 워커 로그
docker compose logs worker-browser # 크롤 워커 로그
docker compose logs -f backend     # 실시간 로그 스트림
```

### 서비스 상태 확인

```bash
docker compose ps
```

### 자주 발생하는 오류

**`POSTGRES_PASSWORD` 관련 오류**
```
error: required variable POSTGRES_PASSWORD is not set
```
→ `.env` 파일이 없거나 `POSTGRES_PASSWORD`가 비어 있습니다. `.env` 파일을 확인하세요.

**Fernet 키 오류**
```
ValueError: Fernet key must be 32 url-safe base64-encoded bytes
```
→ 아래 명령으로 올바른 키를 새로 생성하세요.
```bash
python3 -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

**브라우저 인증 창이 열리지 않음**
- `worker-browser` 서비스가 실행 중인지 확인하세요.
- Docker 환경에서 headful 브라우저는 X11/VNC 설정이 필요합니다. 로컬 개발 환경에서는 정상 동작합니다.

**스캔이 `Analyzing` 단계에서 멈춤**
- `ANTHROPIC_API_KEY`가 올바른지 확인하세요.
- API 사용 한도 초과 여부를 [console.anthropic.com](https://console.anthropic.com) 에서 확인하세요.
- 워커 로그에서 상세 오류를 확인하세요: `docker compose logs worker`

**보고서 PDF 생성 실패**
- `worker` 컨테이너에 WeasyPrint 의존성이 설치되어 있는지 확인하세요.
- HTML 형식으로 먼저 생성해 보세요.

### 데이터 초기화

```bash
docker compose down -v   # 모든 데이터 삭제 후 재시작
docker compose up -d
```

---

## 프로젝트 구조

```
sss-platform/
├── backend/
│   ├── app/
│   │   ├── api/v1/          REST API 엔드포인트
│   │   ├── core/            설정, DB, 보안 유틸
│   │   ├── models/          SQLAlchemy ORM 모델
│   │   ├── schemas/         Pydantic 입출력 스키마
│   │   ├── services/
│   │   │   ├── auth/        브라우저 인증, 세션 관리
│   │   │   ├── crawler/     Playwright 크롤러
│   │   │   ├── collector/   리소스 분류·수집
│   │   │   ├── analysis/    AI 에이전트 오케스트레이터
│   │   │   └── report/      보고서 엔진 + Jinja2 템플릿
│   │   └── workers/         Celery 태스크
│   └── tests/               단위 테스트
├── frontend/
│   └── src/
│       ├── pages/           대시보드, 스캔 생성, 취약점, 보고서
│       ├── components/      공통 UI 컴포넌트
│       ├── hooks/           WebSocket 실시간 진행 훅
│       └── lib/             API 클라이언트
├── infra/nginx/             Nginx 리버스 프록시 설정
├── docs/                    아키텍처, PRD 문서
├── docker-compose.yml
├── Makefile
└── .env.example
```

---

## 라이선스

이 소프트웨어는 권한을 부여받은 보안 테스트 목적으로만 사용해야 합니다.  
허가받지 않은 시스템에 대한 스캔은 관련 법률을 위반할 수 있습니다.

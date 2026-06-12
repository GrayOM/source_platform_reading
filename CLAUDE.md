# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

**SSS Platform** is an AI-powered web application security assessment platform.  
It accepts a target URL, crawls the site with full authentication support, collects client-side resources, runs multi-agent AI analysis, and generates professional vulnerability reports.

```
backend/   FastAPI + Celery + SQLAlchemy + Playwright
frontend/  React 18 + TypeScript + Vite + Tailwind CSS
infra/     Nginx config
docs/      Architecture and product docs
```

## Commands

```bash
# Full stack
make setup        # one-time dev setup
make up           # start all services via docker-compose
make down         # stop all
make test         # backend unit tests
make migrate      # run alembic migrations

# Backend only (dev)
cd backend
source .venv/bin/activate
uvicorn app.main:app --reload --port 8000
celery -A app.core.celery_app worker -Q crawl,auth -c 1   # browser worker
celery -A app.core.celery_app worker -Q default,analysis  # analysis worker

# Frontend only (dev)
cd frontend
npm install && npm run dev      # http://localhost:3000

# Tests
cd backend && python -m pytest tests/ -v
cd backend && python -m pytest tests/test_secret_detector.py -v  # single file
```

## Architecture

### Scan Lifecycle (4 phases)

```
1. AUTH     → BrowserAuthService (Playwright headed) OR cookie/token injection
2. CRAWL    → PlaywrightCrawler (headless, JS rendering, XHR intercept, recursive)
3. ANALYZE  → AnalysisOrchestrator (2 rounds of AI agents)
4. REPORT   → ReportEngine (KISA/OWASP/Executive, PDF/HTML/JSON/MD)
```

### AI Agent Rounds

Round 1 (parallel): `JSAnalyzerAgent`, `SecretDetectorAgent`, `APIMapperAgent`  
Round 2 (sequential, reads prior findings): `AuthAnalyzerAgent`, `BusinessLogicAgent`

Context flows through `AgentContext` shared object. Agents return `FindingCreate[]` which are persisted to DB.

### Key File Locations

| Component | File |
|---|---|
| Scan orchestration (Celery) | `backend/app/workers/scan_worker.py` |
| Playwright crawler | `backend/app/services/crawler/crawler.py` |
| Browser auth capture | `backend/app/services/auth/browser_auth.py` |
| AI orchestrator | `backend/app/services/analysis/orchestrator.py` |
| Agent base class | `backend/app/services/analysis/agents/base_agent.py` |
| Secret detector | `backend/app/services/analysis/agents/secret_detector.py` |
| Report engine | `backend/app/services/report/report_engine.py` |
| Report templates | `backend/app/services/report/templates/` |
| DB models | `backend/app/models/` |
| API routes | `backend/app/api/v1/` |
| WebSocket progress | `backend/app/api/v1/websocket.py` |
| Frontend pages | `frontend/src/pages/` |

### Environment Variables (.env)

```
POSTGRES_PASSWORD     required
SECRET_KEY            required (32+ chars)
FERNET_KEY            required (Fernet key for session encryption)
ANTHROPIC_API_KEY     required for AI analysis
GEMINI_API_KEY        optional fallback
```

## Critical Invariants

- **SSRF protection**: `validate_target_url()` in `security.py` blocks RFC 1918 / loopback addresses. Do not bypass.
- **Session encryption**: Captured cookies/tokens are always AES-256 encrypted via `encrypt_session_data()` before storing in DB.
- **Worker separation**: Browser worker (`-Q crawl,auth`) must run in the `Dockerfile.browser` image which has Playwright installed. The default worker (`-Q default,analysis,reports`) does not need a browser.
- **Finding lifecycle**: Agents persist findings to DB via `AnalysisOrchestrator._persist_findings()`. Never write findings directly to DB in an agent.
- **WebSocket auth**: WS connections require `?token=<access_token>` query param; no anonymous subscriptions.

## Adding a New Agent

1. Create `backend/app/services/analysis/agents/my_agent.py` extending `BaseAgent`
2. Implement `async def analyze(self, context: AgentContext) -> list[FindingCreate]`
3. Add to `AnalysisOrchestrator._agents_round1` or `_agents_round2` in `orchestrator.py`
4. Agent name must match a string identifier for the `agent_name` field in findings

## Database Migrations

After modifying models:
```bash
cd backend
alembic revision --autogenerate -m "describe change"
alembic upgrade head
```

Do not run `git add`, `commit`, `push`, or `merge` unless explicitly asked.

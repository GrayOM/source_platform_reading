# SSS Platform — System Architecture

## 1. High-Level Component Map

```
┌─────────────────────────────────────────────────────────────────┐
│                         User Browser                             │
│              React SPA  (Vite + Tailwind + shadcn/ui)           │
└──────────────────────────┬──────────────────────────────────────┘
                           │  HTTPS / WebSocket
┌──────────────────────────▼──────────────────────────────────────┐
│                      Nginx (TLS termination)                     │
└──────────┬──────────────────────────────────┬───────────────────┘
           │  /api/*                           │  /ws/*
┌──────────▼──────────────────────────────────▼───────────────────┐
│                   FastAPI Application                            │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌────────────────┐  │
│  │ Auth API │  │ Scan API │  │  Report  │  │  WebSocket Hub │  │
│  └──────────┘  └─────┬────┘  │   API    │  └────────────────┘  │
│                      │       └──────────┘                       │
└──────────────────────┼──────────────────────────────────────────┘
                       │  Celery task dispatch
┌──────────────────────▼──────────────────────────────────────────┐
│                      Redis (broker + result)                     │
└──────────────────────┬──────────────────────────────────────────┘
                       │
┌──────────────────────▼──────────────────────────────────────────┐
│                    Celery Workers                                │
│                                                                  │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │                    ScanOrchestrator                      │   │
│  │                                                          │   │
│  │  Phase 1: Auth Setup                                     │   │
│  │    └─ BrowserAuthService (Playwright headed/headless)    │   │
│  │                                                          │   │
│  │  Phase 2: Crawl                                          │   │
│  │    └─ PlaywrightCrawler                                  │   │
│  │         ├─ SitemapBuilder                                │   │
│  │         ├─ ResourceDiscoverer (XHR/Fetch intercept)      │   │
│  │         └─ DownloadManager                               │   │
│  │                                                          │   │
│  │  Phase 3: AI Analysis                                    │   │
│  │    └─ AnalysisOrchestrator                               │   │
│  │         ├─ JSAnalyzerAgent                               │   │
│  │         ├─ SecretDetectorAgent                           │   │
│  │         ├─ AuthAnalyzerAgent                             │   │
│  │         ├─ APIMapperAgent                                │   │
│  │         ├─ BusinessLogicAgent                            │   │
│  │         └─ ReportSynthesisAgent                         │   │
│  │                                                          │   │
│  │  Phase 4: Report                                         │   │
│  │    └─ ReportEngine (KISA / OWASP / Exec Summary)         │   │
│  └──────────────────────────────────────────────────────────┘   │
└──────────────────────────────────────────────────────────────────┘
                       │
        ┌──────────────┴──────────────────────────┐
        │                                         │
┌───────▼──────────┐                   ┌──────────▼───────────┐
│   PostgreSQL      │                   │   Filesystem Storage │
│                   │                   │   /data/scans/        │
│  - users          │                   │     {scan_id}/        │
│  - projects       │                   │       resources/      │
│  - scans          │                   │       reports/        │
│  - sessions       │                   │       screenshots/    │
│  - resources      │                   └──────────────────────┘
│  - findings       │
│  - reports        │
└───────────────────┘
```

---

## 2. Service Boundaries

| Service | Responsibility | Technology |
|---|---|---|
| **FastAPI App** | REST API, JWT auth, WebSocket hub, request validation | FastAPI + Uvicorn |
| **Celery Workers** | Scan execution, analysis, report generation (async) | Celery + Redis |
| **BrowserAuthService** | Headful Playwright session for user-assisted auth | Playwright |
| **PlaywrightCrawler** | Authenticated recursive crawl, JS rendering, resource discovery | Playwright |
| **DownloadManager** | Parallel resource download, deduplication, classification | httpx + aiofiles |
| **AnalysisOrchestrator** | Agent lifecycle management, shared context, result aggregation | asyncio |
| **AI Agents** | Specialized security analysis per domain | Anthropic Claude API |
| **ReportEngine** | Structured finding formatting, template rendering, PDF export | Jinja2 + WeasyPrint |
| **PostgreSQL** | Persistent storage for all entities | asyncpg + SQLAlchemy |
| **Redis** | Celery broker, WebSocket pub/sub, rate limiting | Redis 7 |
| **Nginx** | TLS termination, static file serving, reverse proxy | Nginx |

---

## 3. AI Orchestration Flow

```
AnalysisOrchestrator
│
├─ SharedContext {
│    scan_id, target_url, resources[], sitemap, 
│    js_inventory, endpoint_candidates[], findings_so_far[]
│  }
│
├─ Round 1: Independent agents (parallel)
│    ├─ JSAnalyzerAgent      → js_findings[]
│    ├─ SecretDetectorAgent  → secret_findings[]
│    └─ APIMapperAgent       → endpoint_map{}
│
├─ Merge results → SharedContext.findings_so_far
│
├─ Round 2: Context-aware agents (sequential)
│    ├─ AuthAnalyzerAgent    reads endpoint_map + js_findings → auth_findings[]
│    └─ BusinessLogicAgent   reads all findings → biz_logic_findings[]
│
├─ Merge results → SharedContext.findings_so_far
│
└─ Round 3: Synthesis
     └─ ReportSynthesisAgent → final_findings[] with CVSS, dedup, evidence
```

---

## 4. Database Schema

```
users
  id UUID PK, email UNIQUE, password_hash, full_name, role, created_at

projects
  id UUID PK, user_id FK, name, description, created_at

scans
  id UUID PK, project_id FK, target_url, status ENUM, config JSONB,
  phase ENUM, progress INT, error_message, started_at, completed_at

scan_sessions
  id UUID PK, scan_id FK, auth_method ENUM, cookies_encrypted BYTEA,
  headers_encrypted JSONB, created_at

resources
  id UUID PK, scan_id FK, url TEXT, resource_type ENUM,
  content_hash SHA256, file_path TEXT, size_bytes INT,
  mime_type, is_minified BOOL, source_map_url,
  collected_at, metadata JSONB

findings
  id UUID PK, scan_id FK, resource_id FK nullable, agent_name,
  vulnerability_type, severity ENUM, title, description TEXT,
  evidence JSONB, cwe_id, cvss_score FLOAT, cvss_vector,
  affected_url, affected_parameter, recommendation TEXT,
  status ENUM, analyst_note TEXT, created_at

reports
  id UUID PK, scan_id FK, format ENUM, report_type ENUM,
  file_path TEXT, file_size INT, created_at
```

---

## 5. Authentication Module Design

```
Auth Methods:
  A. Browser-Assisted (Playwright headed)
     User sees a browser → logs in → Playwright captures:
       - All cookies (including httpOnly via CDP)
       - localStorage / sessionStorage
       - Auth headers on outgoing requests

  B. Cookie Import (JSON / Netscape / Burp format)
     Paste or upload → parse → normalize → encrypt → store

  C. Bearer Token / API Key
     Header name + value → encrypt → inject in all crawler requests

Session Storage:
  - AES-256-GCM encryption
  - Key from FERNET_KEY env var
  - Stored in scan_sessions.cookies_encrypted

Crawler Injection:
  - BrowserContext.add_cookies(cookies)
  - BrowserContext.set_extra_http_headers(headers)
```

---

## 6. Crawl Strategy

```
1. Seed URL → Playwright page.goto()
2. Wait for network idle (2 sec)
3. Intercept all network requests via page.route()
   - Capture XHR, Fetch, WS upgrades
   - Record unique endpoints
4. Extract links:
   - <a href>, <link href>, <script src>, <img src>
   - JS: import(), require(), fetch(), axios(), $.ajax()
   - SourceMap references (//# sourceMappingURL)
5. Add new URLs to queue (depth limit, scope filter)
6. Download unique resources to /data/scans/{id}/resources/
7. Build sitemap as adjacency list
8. Screenshot each unique page for report evidence
```

---

## 7. Deployment Architecture

```
docker-compose.yml services:
  - postgres:15      (persistent volume)
  - redis:7          (persistent volume)
  - backend          (FastAPI + Uvicorn, port 8000)
  - worker           (Celery, concurrency=4)
  - worker-browser   (Celery, concurrency=1, Playwright)
  - frontend         (Nginx serving Vite build)
  - nginx            (reverse proxy, TLS)

Data volumes:
  - postgres_data
  - redis_data
  - scan_data:/data/scans

Environment:
  - .env for all secrets
  - No secrets in images
```

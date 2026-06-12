# Product Requirements Document — SSS Platform

## 1. Product Overview

**SSS (Smart Security Scanner)** is an AI-powered web application security assessment platform.  
It accepts a target URL, crawls the site with full authentication support, collects all client-side resources, and runs multi-agent AI analysis to produce professional vulnerability reports.

---

## 2. User Stories

### Authentication & Access
- As a security engineer, I can create an account and manage multiple projects.
- As a tester, I can authenticate to a target site manually in a browser window and have SSS capture the session so it can crawl protected pages.
- As a team lead, I can invite team members to a project and share scan results.

### Scan Lifecycle
- As a tester, I can create a scan by entering a target URL and optional scope rules.
- As a tester, I can see real-time crawl progress including pages discovered, resources collected, and JS files found.
- As a tester, I can pause, resume, or cancel a scan at any time.
- As a tester, I can re-run analysis on previously collected resources without re-crawling.

### Authentication Wizard
- As a tester, I can launch a browser window inside SSS where I manually log in to the target site.
- As a tester, I can import cookies from a Burp Suite or browser export.
- As a tester, I can provide an HTTP header (e.g., `Authorization: Bearer ...`) to authenticate API scans.
- As a tester, the captured session is stored encrypted and used for the entire scan lifecycle.

### Resource Collection
- As a tester, I can view a full inventory of collected resources (JS, HTML, CSS, JSON, source maps).
- As a tester, I can inspect raw resource content within the platform.
- As a tester, I can see which JS files use third-party libraries and their versions.

### AI Analysis
- As a tester, I can view findings organized by severity (Critical / High / Medium / Low / Info).
- As a tester, I can see which agent detected each finding and the evidence used.
- As a tester, I can mark findings as confirmed, false-positive, or out-of-scope.
- As a tester, I can add notes to individual findings.

### Reporting
- As a tester, I can export a professional report in PDF, HTML, Markdown, or JSON.
- As a manager, I can export an executive summary PDF.
- As a tester, I can export a KISA-format report for Korean regulatory submissions.
- As a tester, I can export an OWASP Top 10 mapped report.

---

## 3. MVP Scope

### In MVP
- Single-user mode (no team features)
- URL-based scan creation
- Browser-assisted authentication (headful Playwright window)
- Cookie and Bearer-token auth
- Recursive HTML/JS/CSS/JSON crawling
- JS rendering via Playwright
- Resource inventory with deduplication
- 6 AI analysis agents (JS, secrets, auth, API map, business logic, report synthesis)
- CVSS 3.1 scoring
- PDF + HTML + JSON + Markdown reports
- KISA & OWASP formats
- Real-time WebSocket progress
- Docker Compose deployment

### Post-MVP
- Team / RBAC
- Scheduled / recurring scans
- CI/CD integration (API-first scan trigger)
- Custom agent plugins
- Nuclei template integration
- Chromium extension for cookie capture

---

## 4. UX Flow

```
Landing → Login / Register
  └─ Dashboard (projects + recent scans)
       └─ New Scan
            ├─ Step 1: Target URL + scope
            ├─ Step 2: Authentication Wizard
            │    ├─ Option A: Browser login (headful)
            │    ├─ Option B: Paste cookies (JSON)
            │    └─ Option C: Auth header
            ├─ Step 3: Crawl settings (depth, concurrency, exclusions)
            └─ Step 4: Review → Start
                 └─ Scan Detail (live)
                      ├─ Progress tab (real-time)
                      ├─ Resources tab (inventory)
                      ├─ Findings tab (triaged)
                      └─ Reports tab (generate/export)
```

---

## 5. Security Requirements

- All passwords hashed with bcrypt (cost 12).
- JWT tokens (HS256, 15-min access + 7-day refresh).
- Captured session cookies stored AES-256 encrypted at rest.
- File uploads validated for type and size.
- Scan targets validated against SSRF blocklist (RFC 1918, loopback, link-local).
- Rate limiting: 60 req/min per user on API.
- CSP + HSTS on all frontend responses.
- Audit log for all scan start/stop/delete events.

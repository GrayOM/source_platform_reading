# Repository Guidelines

## Project Structure & Module Organization

This repository contains the SSS Platform, a Dockerized web security scanner MVP. Backend code lives in `backend/app/`: `api/v1` exposes FastAPI routes, `models` and `schemas` hold SQLAlchemy/Pydantic types, `services` contains crawler, analysis, auth, and report logic, and `workers` contains Celery tasks. Backend tests are in `backend/tests`; Alembic migrations are in `backend/alembic`. The React/Vite frontend lives in `frontend/src`, with pages in `pages`, reusable UI in `components`, API helpers in `lib`, and hooks in `hooks`. Documentation is in `docs`, E2E fixtures are in `e2e/vulnerable-site`, and deployment config is in `docker-compose.yml`, `infra/nginx`, and Dockerfiles.

## Build, Test, and Development Commands

- `make setup`: create the backend virtualenv, install dependencies, install Playwright Chromium, and copy `.env.example` if needed.
- `make dev`: start Postgres and Redis, run FastAPI on `8000`, and start Vite on `3000`.
- `make test`: run backend pytest with coverage against `backend/app`.
- `make lint`: run `ruff`, `mypy`, frontend ESLint, and TypeScript type checks.
- `make build`: build Docker Compose images.
- `make up` / `make down`: start or stop the full stack.
- `make migrate`: apply Alembic migrations.

## Coding Style & Naming Conventions

Use Python 3.12 style with 4-space indentation, typed functions where practical, and async APIs for database and web work. Keep backend filenames lowercase with underscores, and name tests `test_*.py`. For React, use TypeScript, PascalCase component/page files such as `ScanDetail.tsx`, and camelCase hooks such as `useScanProgress.ts`. Put shared frontend behavior in `frontend/src/lib` or `frontend/src/hooks`.

## Testing Guidelines

Backend tests use `pytest`, `pytest-asyncio`, and `pytest-cov`. Add focused unit or API tests in `backend/tests` for changed backend behavior, especially scanners, security utilities, auth, and reports. Use `@pytest.mark.asyncio` for async tests. Run `make test` before backend submissions and `make lint` when touching typed Python or frontend code.

## Commit & Pull Request Guidelines

Recent history uses short messages such as `update`, with occasional conventional prefixes like `feat:`. Prefer a clear imperative summary, for example `feat: add report export status` or `fix: harden SSRF validation`. Pull requests should describe the user-visible change, list verification commands, mention config or migration changes, and include screenshots for UI changes. Link related issues when available.

## Security & Configuration Tips

Only scan systems you are authorized to test. Keep secrets out of commits; use `.env` based on `.env.example`. Be careful with `SSRF_ALLOWED_HOSTS`, `ALLOW_PRIVATE_TARGETS`, `SECRET_KEY`, `FERNET_KEY`, and optional AI API keys, especially outside local development or E2E fixtures.

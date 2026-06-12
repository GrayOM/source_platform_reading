.PHONY: help setup dev test lint build clean

help:
	@echo "SSS Platform"
	@echo "  make setup       First-time dev setup"
	@echo "  make dev         Start local dev (requires Docker for postgres+redis)"
	@echo "  make test        Run backend tests"
	@echo "  make lint        Run linters"
	@echo "  make build       Build Docker images"
	@echo "  make up          Start full stack via docker-compose"
	@echo "  make down        Stop docker-compose"
	@echo "  make migrate     Run alembic migrations"
	@echo "  make clean       Remove build artifacts"

setup:
	cd backend && python -m venv .venv && .venv/bin/pip install -r requirements.txt
	cd backend && playwright install chromium
	cd frontend && npm install
	cp -n .env.example .env || true

dev:
	docker compose up postgres redis -d
	cd backend && DATABASE_URL=postgresql+asyncpg://sss:change_me_strong_password@localhost:5432/sss_platform \
	              REDIS_URL=redis://localhost:6379/0 \
	              SECRET_KEY=dev_secret_key_change_me \
	              FERNET_KEY=YourFernetKeyHere12345678901234= \
	              uvicorn app.main:app --reload --port 8000 &
	cd frontend && npm run dev

test:
	cd backend && python -m pytest tests/ -v --cov=app --cov-report=term-missing

lint:
	cd backend && ruff check app/ tests/ && mypy app/
	cd frontend && npm run lint && npm run type-check

build:
	docker compose build

up:
	docker compose up -d
	@echo "Platform running at https://localhost"

down:
	docker compose down

migrate:
	cd backend && alembic upgrade head

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null; true
	find . -name "*.pyc" -delete
	rm -rf frontend/dist backend/.pytest_cache

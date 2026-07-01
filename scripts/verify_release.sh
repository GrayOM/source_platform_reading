#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DOCKER_CONFIG_DIR="${DOCKER_CONFIG_DIR:-/tmp/docker-empty-config}"
RUN_E2E_STACK="${RUN_E2E_STACK:-1}"

cd "$ROOT_DIR"

section() {
  printf '\n==> %s\n' "$1"
}

section "Working tree and secret-like grep"
git status --short
git diff --check
secret_pattern='sk_(test|live)|pk_(test|live)|rk_(test|live)|gh''p_|github''_pat_|A''KIA|A''SIA|xox''b-|xox''p-|Bearer e''yJ'
if git grep -n -E "$secret_pattern"; then
  echo "Secret-like pattern found; review output above." >&2
  exit 1
fi

section "Docker Compose config"
docker compose config >/dev/null

section "Docker image builds"
DOCKER_CONFIG="$DOCKER_CONFIG_DIR" timeout 300 docker compose build backend worker worker-browser
DOCKER_CONFIG="$DOCKER_CONFIG_DIR" timeout 300 docker compose build frontend

if [[ "$RUN_E2E_STACK" == "1" ]]; then
  section "E2E stack"
  timeout 300 docker compose --profile e2e up -d --force-recreate backend worker worker-browser vulnerable-site
  docker compose ps

  section "WeasyPrint PDF smoke"
  docker compose exec worker python -c "from weasyprint import HTML; HTML(string='<h1>SSS PDF OK</h1><p>한글 테스트</p>').write_pdf('/tmp/sss_pdf_smoke.pdf')"
  docker compose exec worker ls -lh /tmp/sss_pdf_smoke.pdf
else
  section "E2E stack skipped"
  echo "RUN_E2E_STACK=$RUN_E2E_STACK"
fi

section "Backend tests"
(
  cd backend
  .venv/bin/python -m pytest tests/ -v
)

section "Frontend build"
(
  cd frontend
  npm run build
)

section "Release verification complete"

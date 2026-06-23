#!/bin/sh
set -e

if [ "$(id -u)" = "0" ] && [ "${SSS_ENTRYPOINT_PRIVILEGED_DONE:-false}" != "true" ]; then
  mkdir -p "${SCAN_DATA_PATH:-/data/scans}"
  chown -R app:app "${SCAN_DATA_PATH:-/data/scans}"
  export SSS_ENTRYPOINT_PRIVILEGED_DONE=true
  exec gosu app "$0" "$@"
fi

if [ "${RUN_MIGRATIONS:-true}" = "true" ]; then
  echo "[entrypoint] running alembic upgrade head"
  if alembic upgrade head; then
    echo "[entrypoint] alembic migration completed"
  else
    code=$?
    echo "[entrypoint] alembic upgrade head failed with exit code ${code}" >&2
    exit "$code"
  fi
fi

exec "$@"

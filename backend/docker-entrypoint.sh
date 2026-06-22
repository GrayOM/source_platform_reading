#!/bin/sh
set -e

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

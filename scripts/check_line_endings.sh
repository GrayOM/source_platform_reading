#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

failed=0

while IFS= read -r -d '' path; do
  case "$path" in
    *.png|*.jpg|*.jpeg|*.gif|*.ico|*.pdf|*.zip|*.gz|*.woff|*.woff2)
      continue
      ;;
  esac

  if [[ -f "$path" ]] && LC_ALL=C grep -Iq . "$path" && LC_ALL=C grep -q $'\r' "$path"; then
    echo "CRLF line ending found: $path" >&2
    failed=1
  fi
done < <(git ls-files -z)

if [[ "$failed" -ne 0 ]]; then
  echo "Normalize line endings to LF before committing." >&2
  exit 1
fi

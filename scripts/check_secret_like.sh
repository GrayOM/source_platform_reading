#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

pattern='sk_(test|live)|pk_(test|live)|rk_(test|live)|gh''p_|github''_pat_|A''KIA|A''SIA|xox''b-|xox''p-|Bearer e''yJ'

if git grep -n -E "$pattern"; then
  echo "Secret-like literal found. Replace test values with placeholders or split string literals." >&2
  exit 1
fi

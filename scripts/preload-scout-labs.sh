#!/usr/bin/env bash
set -euo pipefail

API_URL="${API_URL:-http://localhost:8000}"
CLEAR_FIRST="${CLEAR_FIRST:-true}"
SCOUT_CONTAINER="${SCOUT_CONTAINER:-mucaro-scout-api}"
SQLITE_PATH="${SQLITE_PATH:-/data/mucaro-scout.db}"

cd "$(dirname "${BASH_SOURCE[0]}")/.."

if [[ "${CLEAR_FIRST}" == "true" ]]; then
  echo "Clearing existing Scout SQLite logs from ${SCOUT_CONTAINER}:${SQLITE_PATH}"
  docker exec "${SCOUT_CONTAINER}" python -c "import sqlite3; c=sqlite3.connect('${SQLITE_PATH}'); c.execute('DELETE FROM logs'); c.commit(); print(c.execute('SELECT COUNT(*) FROM logs').fetchone()[0])"
fi

loaded=0
while IFS= read -r file; do
  echo "Loading ${file}"
  curl -fsS -X POST "${API_URL}/ingest/upload" -F "file=@${file}" >/dev/null
  loaded=$((loaded + 1))
done < <(find labs -path '*/data/*.jsonl' -type f ! -name 'combined.jsonl' | sort)

echo "Loaded ${loaded} source files into Scout."
curl -fsS "${API_URL}/health/sqlite"
echo

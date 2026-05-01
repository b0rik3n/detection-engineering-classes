#!/usr/bin/env bash
set -euo pipefail

API_URL=${API_URL:-http://localhost:8000}
FILE=${1:-samples/sample-logs.jsonl}

curl -sS -X POST "$API_URL/ingest/upload" \
  -F "file=@${FILE}"
echo

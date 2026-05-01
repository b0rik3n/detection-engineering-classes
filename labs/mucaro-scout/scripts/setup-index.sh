#!/usr/bin/env bash
set -euo pipefail

OPENSEARCH_URL=${OPENSEARCH_URL:-http://localhost:9200}
INDEX_TEMPLATE_NAME=${INDEX_TEMPLATE_NAME:-logs-normalized-template}
INDEX_NAME=${INDEX_NAME:-logs-normalized}

curl -sS -X PUT "$OPENSEARCH_URL/_index_template/$INDEX_TEMPLATE_NAME" \
  -H 'Content-Type: application/json' \
  --data-binary @scripts/index-template.json

echo
curl -sS -X PUT "$OPENSEARCH_URL/$INDEX_NAME"
echo

echo "Index template and index created."

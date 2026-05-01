# Scaling Notes for 15-20GB Labs

## Host sizing baseline

- 4-8 vCPU
- 16-32GB RAM
- SSD/NVMe preferred

## OpenSearch tuning (single-node class mode)

- Heap: start with 4GB, raise carefully
- Replicas: 0
- Refresh interval: 5s or higher during heavy ingest

## Ingest strategy

- Prefer JSONL for large data
- Chunk large uploads and bulk index in batches
- Add rate limiting/backpressure for concurrent uploads

## Query guardrails

- Always require time range in training exercises
- Cap page size to prevent accidental heavy queries
- Encourage exact-field filters before free-text wildcards

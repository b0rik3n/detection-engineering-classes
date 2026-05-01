# Mucaro Scout

Open-source lightweight JSON log viewer for SOC classrooms, with optional OpenSearch and Splunk lab backends.

This project is an MVP that gives students a lightweight guided log viewer first, then lets instructors expose familiar ELK/Kibana and Splunk workflows when needed:

- Ingest log files (CSV, JSON, JSONL)
- Normalize to canonical fields
- Search SQLite-backed logs with time ranges, field filters, free-text queries, and KQL/ES|QL-style query modes
- Explore data via Kibana-style OpenSearch Dashboards

## Why this exists

In training labs, provisioning full SIEM stacks can be heavy. Mucaro Scout gives instructors and students a lighter, reproducible baseline for 15-20GB lab datasets while preserving core SOC search workflows.

## Architecture

- **SQLite**: default lightweight guided log viewer storage
- **OpenSearch**: optional advanced index + query engine
- **OpenSearch Dashboards**: Kibana-style visualization and ad-hoc exploration
- **FastAPI service**:
  - file ingest endpoint
  - normalization pipeline
  - search API
- **React UI**: Múcaro-style upload and analyst search interface

```
Student/Analyst -> API (/ingest/upload) -> Normalize -> SQLite logs table
Student/Analyst -> API (/search) ---------------------> SQLite query
Student/Analyst -> Dashboards ------------------------> OpenSearch
```

## Canonical normalized schema

Mucaro Scout stores data in a single **ECS-inspired canonical schema**. KQL and ES|QL-style searches are query modes on top of that schema, not separate storage schemas.

Minimum normalized fields:

- `@timestamp` (date)
- `source_ip` (ip)
- `destination_ip` (ip)
- `user` (keyword)
- `host` (keyword)
- `event_type` (keyword)
- `severity` (keyword)
- `raw_message` (text)
- `original` (object, disabled mapping)

## Quickstart

### Prereqs

- Docker + Docker Compose
- curl

### Run stack

```bash
make up
```

Services:

- Scout UI: http://localhost:5173
- API: http://localhost:8000
- OpenSearch: http://localhost:9200
- Dashboards: http://localhost:5601

### Optional Splunk container

Splunk is available as an optional profile for classes that want students to compare workflows against Splunk.

From the UI, click **Splunk** in the top navigation. In local lab mode, Mucaro Scout will ask the API to start the optional Splunk container and then open Splunk Web.

Because this requires Docker socket access, keep this deployment local/trusted only.

```bash
make up-splunk
```

Splunk Web runs on:

```text
http://localhost:8001
```

Default lab credentials:

```text
username: admin
password: admin1234
```

Notes:

- The Splunk container accepts the Splunk license through `SPLUNK_START_ARGS=--accept-license`.
- Override the password with `SPLUNK_PASSWORD=YourStrongPassword make up-splunk`.
- Splunk is intentionally optional because it is heavier than the default OpenSearch stack.

### Initialize index template

```bash
make setup-index
```

### Ingest sample logs

```bash
make ingest-sample
```

### Smoke test API

```bash
make smoke
```

## API usage

### 1) Upload logs

```bash
curl -X POST http://localhost:8000/ingest/upload \
  -F "file=@samples/sample-logs.jsonl"
```

## UI query modes

The frontend includes a query dropdown:

- **KQL**: extracts simple `field: value` filters from the query
- **ES|QL**: extracts simple `WHERE field == value` filters from the query

Examples:

```text
source_ip: "10.0.0.5" and severity: high
FROM logs | WHERE severity == "high" | LIMIT 100
```

Supported file extensions: `.csv`, `.json`, `.jsonl`

### 2) Search logs

```bash
curl -X POST http://localhost:8000/search \
  -H "Content-Type: application/json" \
  -d '{
    "query": "port_scan",
    "start_time": "2026-04-30T00:00:00Z",
    "end_time": "2026-05-01T00:00:00Z",
    "filters": {"severity": "high"},
    "page": 1,
    "size": 50
  }'
```

## 15-20GB classroom scaling notes

This MVP can handle class-scale data if the host is sized correctly.

Recommended starting point:

- CPU: 4-8 vCPU
- RAM: 16-32GB (OpenSearch heap 4-8GB depending on host)
- Storage: SSD/NVMe, 100GB+ free for indices and overhead

Performance tips:

1. Increase ingest batch sizes for larger files.
2. Keep `number_of_replicas: 0` in single-node labs.
3. Use index lifecycle policies to age out stale datasets.
4. Avoid unbounded wildcard queries in class exercises.
5. Keep field mappings stable to prevent mapping explosion.

Operational caution:

- 20GB ingest speed is mostly storage-bound.
- If students upload simultaneously, add queueing/backpressure in API.
- For multi-class usage, shard by index per class or per scenario.

## Open-source publishing (GitHub)

Inside this project directory:

```bash
git add .
git commit -m "Initial MVP: Mucaro Scout ELK-style SOC lab"
git branch -M main
git remote add origin <your-repo-url>
git push -u origin main
```

## Roadmap

- Source-specific parsers: Zeek, Suricata, Sysmon exports
- RBAC and team/class tenancy
- Saved searches + teaching packs
- Detection rule packs (Sigma-inspired)
- Query language helpers and visual timeline

## License

MIT

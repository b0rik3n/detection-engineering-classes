from __future__ import annotations

import csv
import io
import json
import os
import sqlite3
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlparse

import docker
from docker.errors import APIError, DockerException, NotFound
from fastapi import FastAPI, File, HTTPException, Query, UploadFile
from fastapi.middleware.cors import CORSMiddleware
from opensearchpy import OpenSearch
from opensearchpy.exceptions import OpenSearchException
from pydantic import BaseModel, Field

app = FastAPI(title="Mucaro Scout API", version="0.1.0")
cors_origins = os.getenv("CORS_ORIGINS", "*")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"] if cors_origins == "*" else cors_origins.split(","),
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

INDEX_NAME = os.getenv("OPENSEARCH_INDEX", "logs-normalized")
SQLITE_PATH = os.getenv("SQLITE_PATH", "/data/mucaro-scout.db")
SPLUNK_CONTAINER_NAME = os.getenv("SPLUNK_CONTAINER_NAME", "mucaro-splunk")
SPLUNK_IMAGE = os.getenv("SPLUNK_IMAGE", "splunk/splunk:9.4")
SPLUNK_PASSWORD = os.getenv("SPLUNK_PASSWORD", "admin1234")


def _client() -> OpenSearch:
    host = os.getenv("OPENSEARCH_HOST", "opensearch")
    port = int(os.getenv("OPENSEARCH_PORT", "9200"))
    user = os.getenv("OPENSEARCH_USER", "admin")
    password = os.getenv("OPENSEARCH_PASSWORD", "admin")
    return OpenSearch(
        hosts=[{"host": host, "port": port}],
        http_auth=(user, password),
        use_ssl=False,
        verify_certs=False,
    )


def _docker_client() -> docker.DockerClient:
    try:
        return docker.from_env()
    except DockerException as exc:
        raise HTTPException(status_code=503, detail=f"Docker unavailable: {exc}") from exc


def _sqlite_conn() -> sqlite3.Connection:
    os.makedirs(os.path.dirname(SQLITE_PATH), exist_ok=True)
    conn = sqlite3.connect(SQLITE_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            source_ip TEXT,
            destination_ip TEXT,
            user TEXT,
            host TEXT,
            domain TEXT,
            event_type TEXT,
            severity TEXT,
            raw_message TEXT,
            raw_json TEXT NOT NULL
        )
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_source_ip ON logs(source_ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_destination_ip ON logs(destination_ip)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_user ON logs(user)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_host ON logs(host)")
    try:
        conn.execute("ALTER TABLE logs ADD COLUMN domain TEXT")
    except sqlite3.OperationalError as exc:
        if "duplicate column name" not in str(exc):
            raise
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_domain ON logs(domain)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_event_type ON logs(event_type)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_severity ON logs(severity)")
    return conn


def insert_sqlite_events(events: list[dict[str, Any]]) -> int:
    rows = []
    for event in events:
        normalized = normalize_event(event)
        rows.append(
            (
                normalized["@timestamp"],
                normalized.get("source_ip", ""),
                normalized.get("destination_ip", ""),
                normalized.get("user", ""),
                normalized.get("host", ""),
                normalized.get("domain", ""),
                normalized.get("event_type", "unknown"),
                normalized.get("severity", "info"),
                normalized.get("raw_message", ""),
                json.dumps(event),
            )
        )
    with _sqlite_conn() as conn:
        conn.executemany(
            """
            INSERT INTO logs (
                timestamp, source_ip, destination_ip, user, host, domain,
                event_type, severity, raw_message, raw_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            rows,
        )
    return len(rows)


def backfill_sqlite_domains() -> int:
    updated = 0
    with _sqlite_conn() as conn:
        rows = conn.execute(
            "SELECT id, raw_json FROM logs WHERE domain IS NULL OR domain = ''"
        ).fetchall()
        for row in rows:
            try:
                event = json.loads(row["raw_json"])
            except json.JSONDecodeError:
                continue
            domain = extract_domain(event)
            if domain:
                conn.execute("UPDATE logs SET domain = ? WHERE id = ?", (domain, row["id"]))
                updated += 1
    return updated


def _find_splunk_container(client: docker.DockerClient):
    try:
        return client.containers.get(SPLUNK_CONTAINER_NAME)
    except NotFound:
        matches = client.containers.list(all=True, filters={"name": SPLUNK_CONTAINER_NAME})
        for container in matches:
            if container.name == SPLUNK_CONTAINER_NAME:
                return container
    return None


def first_value(event: dict[str, Any], *keys: str, default: str = "") -> Any:
    for key in keys:
        value = event.get(key)
        if value not in (None, ""):
            return value
    return default


def extract_domain(event: dict[str, Any]) -> str:
    value = first_value(event, "domain", "url.domain", "dns.question.name", "query", "query_name", default="")
    if value:
        return str(value)
    url = first_value(event, "url.full", "url", "request.url", default="")
    if url:
        return urlparse(str(url)).hostname or ""
    return ""


def sqlite_like_pattern(value: str, wrap: bool = False) -> str:
    """Convert Scout wildcards to a SQLite LIKE pattern.

    Users can search with shell/KQL-style wildcards:
    - * matches any number of characters
    - ? matches one character

    Literal SQLite wildcard characters are escaped first so user input does not
    accidentally become broader than intended.
    """
    escaped = (
        value.replace("\\", "\\\\")
        .replace("%", "\\%")
        .replace("_", "\\_")
        .replace("*", "%")
        .replace("?", "_")
    )
    return f"%{escaped}%" if wrap and "%" not in escaped and "_" not in escaped else escaped


def raw_json_value_like_pattern(value: str) -> str:
    pattern = sqlite_like_pattern(value, wrap=True)
    if not pattern.startswith("%"):
        pattern = f"%{pattern}"
    if not pattern.endswith("%"):
        pattern = f"{pattern}%"
    return pattern


def normalize_event(event: dict[str, Any]) -> dict[str, Any]:
    now = datetime.now(timezone.utc).isoformat()
    ts = first_value(event, "@timestamp", "timestamp", "time", "event_time", default=now)
    source_ip = first_value(event, "source_ip", "source.ip", "src_ip", "src", "client.ip")
    destination_ip = first_value(
        event,
        "destination_ip",
        "destination.ip",
        "dst_ip",
        "dst",
        "server.ip",
    )
    user = first_value(event, "user", "user.name", "username", "account", "principal")
    host = first_value(event, "host", "host.name", "hostname", "device", "observer.name")
    domain = extract_domain(event)
    event_type = first_value(
        event,
        "event_type",
        "event.action",
        "event.category",
        "event.dataset",
        "type",
        "category",
        default="unknown",
    )
    severity = first_value(event, "severity", "event.severity", "log.level", "level", default="info")
    raw_message = first_value(event, "raw_message", "message", "event.original", default=json.dumps(event))

    normalized = {
        "@timestamp": ts,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "user": user,
        "host": host,
        "domain": domain,
        "event_type": event_type,
        "severity": str(severity),
        "raw_message": raw_message,
        "original": event,
    }

    # Preserve common ECS-style dotted fields as first-class display/search fields too.
    for key in ("source.ip", "destination.ip", "user.name", "host.name", "domain", "url.domain", "dns.question.name", "event.action", "event.category", "event.dataset", "event.severity", "log.level"):
        if key in event:
            normalized[key] = event[key]

    return normalized


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health/sqlite")
def sqlite_health() -> dict[str, Any]:
    with _sqlite_conn() as conn:
        count = conn.execute("SELECT COUNT(*) AS count FROM logs").fetchone()["count"]
    return {"status": "ok", "path": SQLITE_PATH, "count": count}


@app.post("/maintenance/sqlite/backfill-domains")
def sqlite_backfill_domains() -> dict[str, Any]:
    updated = backfill_sqlite_domains()
    return {"status": "ok", "updated": updated}


@app.get("/health/opensearch")
def opensearch_health() -> dict[str, Any]:
    try:
        info = _client().info()
        return {"status": "ok", "cluster_name": info.get("cluster_name", "unknown")}
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"OpenSearch unavailable: {exc}") from exc


@app.post("/integrations/splunk/start")
def start_splunk() -> dict[str, Any]:
    """Start the optional Splunk lab container on demand.

    This endpoint is intended for local classroom/lab deployments only because it
    requires Docker socket access from the API container.
    """
    client = _docker_client()
    try:
        container = _find_splunk_container(client)
        if container is not None:
            if container.status != "running":
                container.start()
                container.reload()
            return {
                "status": container.status,
                "container": SPLUNK_CONTAINER_NAME,
                "url": "http://localhost:8001",
                "message": "Splunk is running or starting. First boot may take several minutes.",
            }
    except DockerException as exc:
        raise HTTPException(status_code=503, detail=f"Could not inspect Splunk container: {exc}") from exc

    try:
        client.images.pull(SPLUNK_IMAGE)
        client.containers.run(
            SPLUNK_IMAGE,
            name=SPLUNK_CONTAINER_NAME,
            detach=True,
            environment={
                "SPLUNK_START_ARGS": "--accept-license",
                "SPLUNK_PASSWORD": SPLUNK_PASSWORD,
            },
            ports={
                "8000/tcp": 8001,
                "8088/tcp": 8088,
                "9997/tcp": 9997,
            },
            volumes={
                "mucaro-scout_splunk-data": {"bind": "/opt/splunk/var", "mode": "rw"},
                "mucaro-scout_splunk-etc": {"bind": "/opt/splunk/etc", "mode": "rw"},
            },
        )
        return {
            "status": "starting",
            "container": SPLUNK_CONTAINER_NAME,
            "url": "http://localhost:8001",
            "message": "Splunk image pulled and container started. First boot may take several minutes.",
        }
    except APIError as exc:
        if exc.status_code == 409:
            container = _find_splunk_container(client)
            if container is not None:
                if container.status != "running":
                    container.start()
                    container.reload()
                return {
                    "status": container.status,
                    "container": SPLUNK_CONTAINER_NAME,
                    "url": "http://localhost:8001",
                    "message": "Existing Splunk container found and started.",
                }
        raise HTTPException(status_code=503, detail=f"Could not start Splunk: {exc}") from exc
    except DockerException as exc:
        raise HTTPException(status_code=503, detail=f"Could not start Splunk: {exc}") from exc


@app.post("/ingest/upload")
async def ingest_upload(file: UploadFile = File(...)) -> dict[str, Any]:
    data = await file.read()
    text = data.decode("utf-8", errors="ignore")
    ext = (file.filename or "").lower()

    parsed: list[dict[str, Any]] = []

    if ext.endswith(".jsonl"):
        for line in text.splitlines():
            if line.strip():
                parsed.append(json.loads(line))
    elif ext.endswith(".json"):
        obj = json.loads(text)
        if isinstance(obj, list):
            parsed.extend(obj)
        elif isinstance(obj, dict):
            parsed.append(obj)
        else:
            raise HTTPException(status_code=400, detail="Unsupported JSON structure")
    elif ext.endswith(".csv"):
        reader = csv.DictReader(io.StringIO(text))
        parsed.extend(reader)
    else:
        raise HTTPException(status_code=400, detail="Supported formats: .csv .json .jsonl")

    if not parsed:
        return {"ingested": 0}

    ingested = insert_sqlite_events(parsed)
    return {"ingested": ingested, "backend": "sqlite", "errors": False}


class SearchRequest(BaseModel):
    query: str | None = None
    start_time: str | None = None
    end_time: str | None = None
    filters: dict[str, str] = Field(default_factory=dict)
    page: int = 1
    size: int = 100


@app.post("/search")
def search_logs(req: SearchRequest) -> dict[str, Any]:
    if req.page < 1:
        raise HTTPException(status_code=400, detail="page must be >= 1")
    if req.size < 1 or req.size > 1000:
        raise HTTPException(status_code=400, detail="size must be between 1 and 1000")

    where: list[str] = []
    params: list[Any] = []

    if req.query:
        like = sqlite_like_pattern(req.query, wrap=True)
        where.append(
            "(raw_message LIKE ? ESCAPE '\\' OR raw_json LIKE ? ESCAPE '\\' OR event_type LIKE ? ESCAPE '\\' OR host LIKE ? ESCAPE '\\' OR user LIKE ? ESCAPE '\\' OR domain LIKE ? ESCAPE '\\' OR severity LIKE ? ESCAPE '\\')"
        )
        params.extend([like, like, like, like, like, like, like])

    field_map = {
        "@timestamp": "timestamp",
        "timestamp": "timestamp",
        "source_ip": "source_ip",
        "source.ip": "source_ip",
        "destination_ip": "destination_ip",
        "destination.ip": "destination_ip",
        "user": "user",
        "user.name": "user",
        "host": "host",
        "host.name": "host",
        "domain": "domain",
        "url.domain": "domain",
        "dns.question.name": "domain",
        "event_type": "event_type",
        "event.action": "event_type",
        "severity": "severity",
    }
    for key, value in req.filters.items():
        column = field_map.get(key)
        if column:
            if "*" in value or "?" in value:
                where.append(f"{column} LIKE ? ESCAPE '\\'")
                params.append(sqlite_like_pattern(value))
            else:
                where.append(f"{column} = ?")
                params.append(value)
        else:
            where.append("(raw_json LIKE ? ESCAPE '\\' AND raw_json LIKE ? ESCAPE '\\')")
            params.append(f'%"{key}"%')
            params.append(raw_json_value_like_pattern(value))

    if req.start_time:
        where.append("timestamp >= ?")
        params.append(req.start_time)
    if req.end_time:
        where.append("timestamp <= ?")
        params.append(req.end_time)

    where_sql = f"WHERE {' AND '.join(where)}" if where else ""
    offset = (req.page - 1) * req.size
    with _sqlite_conn() as conn:
        total = conn.execute(f"SELECT COUNT(*) AS count FROM logs {where_sql}", params).fetchone()["count"]
        rows = conn.execute(
            f"""
            SELECT * FROM logs
            {where_sql}
            ORDER BY timestamp DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            [*params, req.size, offset],
        ).fetchall()

    results = []
    for row in rows:
        results.append(
            {
                "@timestamp": row["timestamp"],
                "source_ip": row["source_ip"],
                "destination_ip": row["destination_ip"],
                "user": row["user"],
                "host": row["host"],
                "domain": row["domain"],
                "event_type": row["event_type"],
                "severity": row["severity"],
                "raw_message": row["raw_message"],
                "original": json.loads(row["raw_json"]),
            }
        )
    return {"total": total, "page": req.page, "size": req.size, "backend": "sqlite", "results": results}


@app.get("/search")
def search_logs_get(
    query: str | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
    page: int = Query(1, ge=1),
    size: int = Query(100, ge=1, le=1000),
) -> dict[str, Any]:
    req = SearchRequest(query=query, start_time=start_time, end_time=end_time, page=page, size=size)
    return search_logs(req)

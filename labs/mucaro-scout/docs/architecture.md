# Architecture

## Components

1. OpenSearch
   - Stores normalized log events
   - Handles filtering, full-text search, and time-sorted retrieval

2. OpenSearch Dashboards
   - Ad-hoc exploration
   - Quick visual pivots for classroom exercises

3. FastAPI service
   - `/ingest/upload` parses and normalizes raw files
   - `/search` translates analyst filters into OpenSearch queries

## Data flow

- Upload file -> parse by type -> normalize -> bulk index
- Search request -> build bool query -> return paginated events

## Design intent

Keep this simple and educational. It should be easy for students to inspect, modify, and extend.

# Data Model

Canonical fields used by the search workflow:

- `@timestamp`: event time in ISO-8601
- `source_ip`: source IP
- `destination_ip`: destination IP
- `user`: account/user principal
- `host`: host/device name
- `event_type`: normalized event category
- `severity`: info/low/medium/high/critical
- `raw_message`: text body for free-text search
- `original`: full original object (stored, not indexed)

## Mapping strategy

- Keyword for exact filters
- Text for `raw_message` free-text
- Date for time filtering
- IP fields for network analytics extensions

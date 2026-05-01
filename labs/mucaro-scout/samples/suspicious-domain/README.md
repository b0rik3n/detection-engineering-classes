# Suspicious Domain Lab

Scenario: users repeatedly resolve and connect to `sfrclak.com` (`142.11.206.73`). Students should correlate DNS, proxy, firewall, auth, and endpoint activity to identify affected hosts and users.

Files:

- `dns.jsonl` - DNS query activity
- `proxy.jsonl` - HTTP/proxy requests
- `firewall.jsonl` - allow/block network telemetry
- `auth.jsonl` - authentication context
- `endpoint.jsonl` - process execution context
- `combined.jsonl` - all events merged and sorted by timestamp

Each source file contains 100 events. Upload files individually to teach source-by-source investigation, or upload `combined.jsonl` for a quick demo.

Suggested searches:

- `sfrclak.com`
- `142.11.206.73`
- `domain: sfrclak.com`
- `event_type: dns_query`
- `severity: critical`

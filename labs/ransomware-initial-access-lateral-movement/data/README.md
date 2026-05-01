# ransomware-initial-access-lateral-movement data pack

Scenario: Initial access followed by credential access, lateral movement, and ransomware staging.

Files:

- `endpoint.jsonl` - 100 synthetic endpoint events
- `auth.jsonl` - 100 synthetic auth events
- `smb.jsonl` - 100 synthetic smb events
- `dns.jsonl` - 100 synthetic dns events
- `firewall.jsonl` - 100 synthetic firewall events
- `combined.jsonl` - 500 events merged and sorted by timestamp

Suggested searches:

- `rclone.exe`
- `failed_login`
- `admin$`
- `severity: critical`

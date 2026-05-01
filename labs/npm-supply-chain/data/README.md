# npm-supply-chain data pack

Scenario: npm supply-chain compromise with suspicious postinstall execution and C2 traffic.

Files:

- `package.jsonl` - 100 synthetic package events
- `endpoint.jsonl` - 100 synthetic endpoint events
- `proxy.jsonl` - 100 synthetic proxy events
- `dns.jsonl` - 100 synthetic dns events
- `auth.jsonl` - 100 synthetic auth events
- `combined.jsonl` - 500 events merged and sorted by timestamp

Suggested searches:

- `npm-assets-cache.net`
- `postinstall`
- `event_type: process_start`
- `severity: critical`

# browser-extension-supply-chain-risk data pack

Scenario: Malicious browser extension update creates suspicious outbound behavior.

Files:

- `browser.jsonl` - 100 synthetic browser events
- `endpoint.jsonl` - 100 synthetic endpoint events
- `proxy.jsonl` - 100 synthetic proxy events
- `dns.jsonl` - 100 synthetic dns events
- `identity.jsonl` - 100 synthetic identity events
- `combined.jsonl` - 500 events merged and sorted by timestamp

Suggested searches:

- `cdn-update-service.com`
- `extension_update`
- `chrome.exe`
- `severity: high`

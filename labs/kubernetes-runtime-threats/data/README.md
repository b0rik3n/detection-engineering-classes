# kubernetes-runtime-threats data pack

Scenario: Kubernetes runtime compromise with suspicious pod exec and crypto-mining behavior.

Files:

- `kube-audit.jsonl` - 100 synthetic kube-audit events
- `container.jsonl` - 100 synthetic container events
- `network.jsonl` - 100 synthetic network events
- `node.jsonl` - 100 synthetic node events
- `cloud.jsonl` - 100 synthetic cloud events
- `combined.jsonl` - 500 events merged and sorted by timestamp

Suggested searches:

- `xmrig`
- `pods/exec`
- `privileged`
- `severity: critical`

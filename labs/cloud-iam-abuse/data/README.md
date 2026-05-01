# cloud-iam-abuse data pack

Scenario: Compromised cloud identity performs privilege discovery and role escalation.

Files:

- `cloudtrail.jsonl` - 100 synthetic cloudtrail events
- `signin.jsonl` - 100 synthetic signin events
- `iam.jsonl` - 100 synthetic iam events
- `vpc-flow.jsonl` - 100 synthetic vpc-flow events
- `edr.jsonl` - 100 synthetic edr events
- `combined.jsonl` - 500 events merged and sorted by timestamp

Suggested searches:

- `AssumeRole`
- `AttachUserPolicy`
- `203.0.113.25`
- `severity: high`

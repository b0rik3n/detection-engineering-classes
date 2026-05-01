# m365-oauth-app-abuse data pack

Scenario: Malicious OAuth application consent and mailbox access in Microsoft 365.

Files:

- `audit.jsonl` - 100 synthetic audit events
- `signin.jsonl` - 100 synthetic signin events
- `oauth.jsonl` - 100 synthetic oauth events
- `graph.jsonl` - 100 synthetic graph events
- `mailbox.jsonl` - 100 synthetic mailbox events
- `combined.jsonl` - 500 events merged and sorted by timestamp

Suggested searches:

- `Mail.ReadWrite`
- `Consent to application`
- `203.0.113.25`
- `severity: high`

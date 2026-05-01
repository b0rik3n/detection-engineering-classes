# ot-ics-protocol-misuse-advanced data pack

Scenario: Advanced OT protocol misuse with staged discovery and unsafe write activity.

Files:

- `modbus.jsonl` - 100 synthetic modbus events
- `dnp3.jsonl` - 100 synthetic dnp3 events
- `opcua.jsonl` - 100 synthetic opcua events
- `firewall.jsonl` - 100 synthetic firewall events
- `asset.jsonl` - 100 synthetic asset events
- `combined.jsonl` - 500 events merged and sorted by timestamp

Suggested searches:

- `write_multiple_registers`
- `operate`
- `firmware_update`
- `severity: critical`

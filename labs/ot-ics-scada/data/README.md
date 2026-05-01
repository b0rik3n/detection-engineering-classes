# ot-ics-scada data pack

Scenario: Unauthorized engineering workstation activity against OT/ICS assets.

Files:

- `modbus.jsonl` - 100 synthetic modbus events
- `firewall.jsonl` - 100 synthetic firewall events
- `engineering-workstation.jsonl` - 100 synthetic engineering-workstation events
- `asset.jsonl` - 100 synthetic asset events
- `auth.jsonl` - 100 synthetic auth events
- `combined.jsonl` - 500 events merged and sorted by timestamp

Suggested searches:

- `write_multiple_registers`
- `10.77.4.50`
- `event_type: plc_write`
- `severity: critical`

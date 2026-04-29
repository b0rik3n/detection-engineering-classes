# Instructor Answer Key (OT/ICS/SCADA)

## Expected findings
- IOC hits for suspicious external infrastructure (`185.244.25.12`, `update-plc-service.net`).
- ICS write/program operations from engineering workstation context.
- Correlated high-confidence events where engineering host, ICS write action, and suspicious outbound traffic occur in a 30-minute window.

## ATT&CK for ICS examples
- Initial Access / Execution (context-dependent)
- Command and Control
- Impair Process Control / Modify Control Logic (if logic write/programming observed)

## Minimum passing
- IOC, behavior, and correlation detections in both SPL and ES|QL.
- Basic ATT&CK for ICS mapping with rationale.

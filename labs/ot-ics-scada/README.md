# de-lab-ot-ics-scada

Detection engineering lab for OT/ICS/SCADA environments using Splunk (SPL) and Elastic (Kibana + ES|QL).

## Core objective
Students build equivalent detections across both platforms and compare tradeoffs in precision, performance, and maintainability.

## Real-incident grounding
This lab is now grounded in publicly reported OT/ICS patterns seen in the FrostyGoop reporting cycle (Modbus-focused disruptive activity), while keeping a synthetic dataset for safe classroom use.

Reference articles:
- Dragos Intel Brief: https://hub.dragos.com/report/frostygoop-ics-malware-impacting-operational-technology
- Dragos blog (context + defensive guidance): https://www.dragos.com/blog/protect-against-frostygoop-ics-malware-targeting-operational-technology

## Lab modules
1. OT/ICS data familiarization (industrial protocols + asset context)
2. IOC detections (malicious IP/domain/hash where applicable)
3. Behavioral detections (unauthorized PLC/programming actions)
4. Correlation detection (engineering workstation + protocol action + network anomaly)
5. Kibana practical (Discover + ES|QL + rule creation)
6. Analyst write-up and ATT&CK for ICS mapping

## Structure
- `exercise/` student handouts and instructions
- `splunk/` SPL starter queries
- `elastic/esql/` ES|QL starter queries
- `kibana/` checklist and practical tasks
- `data/` synthetic OT/ICS events
- `instructor/` answer key + rubric

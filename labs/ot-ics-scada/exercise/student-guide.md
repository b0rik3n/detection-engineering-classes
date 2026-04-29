# Student Guide: OT/ICS/SCADA Detection Engineering Lab

## Scenario
A suspected intrusion targeted an industrial environment. Logs show abnormal engineering workstation behavior, suspicious ICS protocol write/program actions, and unusual outbound traffic.

This scenario is inspired by publicly reported OT incidents involving disruptive ICS malware patterns (especially Modbus-manipulation behavior discussed in FrostyGoop reporting), adapted to synthetic classroom data.

## Training references (read first)
- Dragos Intel Brief: https://hub.dragos.com/report/frostygoop-ics-malware-impacting-operational-technology
- Dragos defensive overview: https://www.dragos.com/blog/protect-against-frostygoop-ics-malware-targeting-operational-technology

## Your mission
Build and tune detections in both Splunk and Elastic for:
1. IOC detections
2. Behavioral detections
3. Correlation detections

## Deliverables
- SPL queries (IOC/behavior/correlation)
- ES|QL queries (IOC/behavior/correlation)
- Kibana investigation evidence
- ATT&CK for ICS mapping
- 1-page comparison (SPL vs ES|QL)

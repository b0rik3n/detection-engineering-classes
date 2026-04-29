# Extended Student Handout (Beginner-Friendly)
## OT/ICS/SCADA Detection Engineering Practical

## What this lab teaches
You will investigate suspicious activity in an OT/ICS network and write detections in both Splunk and Elastic.

## Real-world context for this lab
This lab is based on publicly discussed OT/ICS attack patterns from the FrostyGoop reporting cycle, especially suspicious Modbus write/manipulation behavior and engineering-workstation-driven control actions.

Training references:
1. Dragos Intel Brief: https://hub.dragos.com/report/frostygoop-ics-malware-impacting-operational-technology
2. Dragos defensive overview: https://www.dragos.com/blog/protect-against-frostygoop-ics-malware-targeting-operational-technology

Note: our class data is synthetic, but the behavioral patterns are intentionally aligned to real reporting themes.

## Quick glossary
- OT: Operational Technology systems used to run physical processes.
- ICS/SCADA: Industrial control systems and supervisory control networks.
- PLC: Programmable Logic Controller.
- HMI: Human-Machine Interface.
- Engineering workstation: host used to configure/control PLCs.
- Behavioral detection: logic based on suspicious actions.
- Correlation: joining multiple suspicious signals into one higher-confidence alert.

## Step-by-step
1. Validate data visibility in Splunk and Kibana.
2. Identify key fields and map Splunk fields to ECS fields.
3. Run IOC detections.
4. Run behavior detections for unauthorized write/program commands.
5. Run correlation detections for high-confidence incidents.
6. Build 3 Elastic rules (IOC/behavior/correlation).
7. Submit ATT&CK for ICS mapping and platform comparison.

See starter queries in `splunk/` and `elastic/esql/`.

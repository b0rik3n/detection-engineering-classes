# de-lab-iran-cyber-risk-escalation-20260430-2055

Detection engineering lab based on Unit 42's **Threat Brief: Escalation of Cyber Risk Related to Iran (Updated April 17)**.

Timestamped class name: `iran-cyber-risk-escalation-20260430-2055`

## Scenario

After regional military escalation and a 47-day near-complete Iranian internet outage, defenders observe renewed cyber risk related to Iran-aligned activity. The lab includes synthetic telemetry for conflict-themed phishing and fraud, hacktivist DDoS, possible VSAT/Starlink egress, destructive/wiper behavior, and OT/ICS targeting of Rockwell Automation / Allen-Bradley / FactoryTalk-style services by CL-STA-1128 / Cyber Av3ngers / Storm-0784.

## Known indicators and behaviors

- Threat cluster names: `CL-STA-1128`, `Cyber Av3ngers`, `Storm-0784`
- Phishing/fraud domains: `iranforward.org, trumpvsirancoin.xyz, emiratescryptobank.com, emiratesinvestunion.com, emirates-post-payments.com, saudi-erp-login.com`
- OT/ICS targets: `FactoryTalk, Allen-Bradley, Rockwell Automation, Unitronics PLC`
- DDoS behaviors: `http_flood, udp_flood, syn_flood`
- Wiper families: `SHAMOON-LIKE-WIPER, ZEROCLEAR-LIKE-WIPER, DISK_ERASE_TOOL`
- Infrastructure terms: `Starlink/VSAT`, `FactoryTalk`, `Allen-Bradley`, `Rockwell Automation`

## Learning objectives

- Detect conflict-themed phishing and fraud infrastructure
- Identify DDoS and hacktivist disruption patterns
- Hunt OT/ICS reconnaissance against FactoryTalk / Allen-Bradley services
- Correlate destructive wiper behavior with network and identity context
- Separate article-derived threat intelligence from synthetic lab evidence

## Structure

- `data/` source-separated synthetic logs
- `exercise/` student guide
- `splunk/` SPL starter searches
- `elastic/esql/` ES|QL starter searches
- `kibana/` checklist
- `instructor/` answer key

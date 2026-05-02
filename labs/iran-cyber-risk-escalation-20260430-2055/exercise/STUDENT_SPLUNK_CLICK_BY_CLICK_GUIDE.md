# Student Splunk Click-by-Click Guide

Lab: `iran-cyber-risk-escalation-20260430-2055`

This guide is Splunk-only and walks you from data load to final detection write-up.

---

## 1) Load lab data into Splunk

1. Open Splunk Web.
2. Go to **Settings** → **Add Data**.
3. Click **Upload**.
4. Upload `combined.jsonl` first:

```text
labs/iran-cyber-risk-escalation-20260430-2055/data/combined.jsonl
```

5. Source type: choose `_json` (or JSON auto-detect).
6. Host value: automatic is fine.
7. Set destination index (recommended): `de_iran_lab`.
8. Click **Review** → **Submit**.
9. Repeat upload for Palo Alto logs to the same index:

```text
labs/iran-cyber-risk-escalation-20260430-2055/data/paloalto-firewall.jsonl
```

10. Open **Search & Reporting**.
11. Set time picker to **All time**.

Quick validation search:

```spl
index=de_iran_lab | stats count
```

Expected: around 1,020 events (700 combined + 320 Palo Alto).

---

## 2) Baseline and quick triage

Run:

```spl
index=de_iran_lab
| stats count by event.dataset
| sort - count
```

Then:

```spl
index=de_iran_lab
| stats earliest(_time) as first latest(_time) as last count
| convert ctime(first) ctime(last)
```

---

## 3) Hunt phishing/fraud infrastructure

### 3.1 Domain IOC sweep

```spl
index=de_iran_lab (domain="iranforward.org" OR domain="trumpvsirancoin.xyz" OR domain="emiratescryptobank.com" OR domain="emiratesinvestunion.com" OR domain="emirates-post-payments.com")
| table _time event.dataset host.name user.name source.ip destination.ip domain event.action severity message
| sort _time
```

### 3.2 Who touched suspicious domains most

```spl
index=de_iran_lab (domain="iranforward.org" OR domain="trumpvsirancoin.xyz" OR domain="emiratescryptobank.com" OR domain="emiratesinvestunion.com" OR domain="emirates-post-payments.com")
| stats count values(domain) as domains values(event.dataset) as datasets by host.name user.name source.ip
| sort - count
```

---

## 4) OT/ICS targeting analysis

### 4.1 Vendor/tooling keywords

```spl
index=de_iran_lab ("FactoryTalk" OR "Allen-Bradley" OR "Rockwell Automation" OR "Unitronics")
| table _time event.dataset host.name user.name source.ip destination.ip event.action event_type severity message
| sort _time
```

### 4.2 Threat-cluster terms

```spl
index=de_iran_lab ("CL-STA-1128" OR "Cyber Av3ngers" OR "Storm-0784")
| table _time event.dataset host.name user.name source.ip destination.ip event.action event_type severity message
| sort _time
```

### 4.3 OT/ICS-only pivot

```spl
index=de_iran_lab event.dataset="ot-ics"
| stats count values(event_type) as event_types values(source.ip) as src values(destination.ip) as dst by host.name user.name
| sort - count
```

---

## 5) DDoS and disruption patterns

### 5.1 DDoS events

```spl
index=de_iran_lab event.dataset="ddos" (ddos_spike OR http_flood OR udp_flood OR syn_flood)
| timechart span=5m count by event_type
```

### 5.2 Top DDoS targets

```spl
index=de_iran_lab event.dataset="ddos" (ddos_spike OR http_flood OR udp_flood OR syn_flood)
| stats count values(event_type) as flood_types by destination.ip destination.port
| sort - count
```

---

## 6) Firewall + Palo Alto specific hunt

First verify Palo Alto ingestion:

```spl
index=de_iran_lab event.dataset="panw.panos" | stats count
```

Expected: 320 events.

### 6.1 Generic suspicious egress

```spl
index=de_iran_lab event.dataset=firewall ("Starlink/VSAT" OR vsat_starlink_egress)
| table _time host.name user.name source.ip destination.ip destination.port domain event.action network.provider severity
| sort _time
```

### 6.2 Palo Alto dataset analysis

```spl
index=de_iran_lab event.dataset="panw.panos"
| stats count by panw.panos.type panw.panos.subtype panw.panos.rule panw.panos.action
| sort - count
```

### 6.3 Palo Alto threat/high-severity events

```spl
index=de_iran_lab event.dataset="panw.panos" (panw.panos.type="THREAT" OR panw.panos.severity="high" OR panw.panos.severity="critical")
| table _time host.name user.name source.ip destination.ip domain panw.panos.type panw.panos.subtype panw.panos.rule panw.panos.threat.name panw.panos.severity event.action
| sort _time
```

---

## 7) Wiper/destructive behavior

### 7.1 Wiper family and behavior search

```spl
index=de_iran_lab event.dataset=wiper (wiper_execution OR "SHAMOON-LIKE-WIPER" OR "ZEROCLEAR-LIKE-WIPER" OR "DISK_ERASE_TOOL")
| table _time host.name user.name process.name process.command_line event_type severity message
| sort _time
```

### 7.2 Most affected hosts

```spl
index=de_iran_lab event.dataset=wiper (wiper_execution OR "SHAMOON-LIKE-WIPER" OR "ZEROCLEAR-LIKE-WIPER" OR "DISK_ERASE_TOOL")
| stats count values(event_type) as behaviors by host.name user.name
| sort - count
```

---

## 8) Build full incident timeline in Splunk

Run:

```spl
index=de_iran_lab (domain="iranforward.org" OR domain="trumpvsirancoin.xyz" OR domain="emiratescryptobank.com" OR domain="emiratesinvestunion.com" OR domain="emirates-post-payments.com" OR "FactoryTalk" OR "Allen-Bradley" OR "Rockwell Automation" OR ddos_spike OR wiper_execution OR event.dataset="panw.panos")
| eval indicator=coalesce(domain,event_type,panw.panos.threat.name,event.action)
| table _time event.dataset host.name user.name source.ip destination.ip destination.port indicator event.action event_type severity message
| sort _time
```

Export this as CSV for submission.

---

## 9) Create detections in SPL

### Detection 1: phishing/fraud domains

```spl
index=de_iran_lab (domain="iranforward.org" OR domain="trumpvsirancoin.xyz" OR domain="emiratescryptobank.com" OR domain="emiratesinvestunion.com" OR domain="emirates-post-payments.com")
| stats count values(domain) as domains by host.name user.name source.ip
```

### Detection 2: OT/ICS targeting terms

```spl
index=de_iran_lab event.dataset="ot-ics" ("FactoryTalk" OR "Allen-Bradley" OR "Rockwell Automation" OR "Unitronics")
| stats count values(event_type) as event_types by source.ip destination.ip host.name
```

### Detection 3: DDoS spike behavior

```spl
index=de_iran_lab event.dataset="ddos" (ddos_spike OR http_flood OR udp_flood OR syn_flood)
| bucket _time span=5m
| stats count by _time destination.ip event_type
| where count > 10
```

### Detection 4: Palo Alto high-risk threat events

```spl
index=de_iran_lab event.dataset="panw.panos" panw.panos.type="THREAT" (panw.panos.severity="high" OR panw.panos.severity="critical")
| stats count values(panw.panos.threat.name) as threats by host.name source.ip destination.ip domain panw.panos.rule
```

### Detection 5: destructive endpoint behavior

```spl
index=de_iran_lab event.dataset=wiper (wiper_execution OR "SHAMOON-LIKE-WIPER" OR "ZEROCLEAR-LIKE-WIPER" OR "DISK_ERASE_TOOL")
| stats count values(process.command_line) as cmds by host.name user.name
```

---

## 10) Deliverable checklist

Your submission should include:

- [ ] confirmed ingestion and dataset counts
- [ ] phishing/fraud IOC findings
- [ ] OT/ICS targeting findings
- [ ] DDoS/disruption findings
- [ ] Palo Alto threat findings
- [ ] wiper/destructive findings
- [ ] full timeline
- [ ] at least 5 SPL detections with tuning notes

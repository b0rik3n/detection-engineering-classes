# Student Splunk Click-by-Click Guide

Lab: `iran-cyber-risk-escalation-20260430-2055`

Source article:
- Unit 42 Threat Brief: Escalation of Cyber Risk Related to Iran (Updated April 17)
- https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/

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

### Query: total ingestion check

```spl
index=de_iran_lab | stats count
```

**Description**
- Confirms how many total events are in your class index.

**How it works**
- `index=de_iran_lab`: search only your lab index.
- `stats count`: return one total number.

**How to interpret**
- Expected around 1,020 events (700 combined + 320 Palo Alto).

---

## 2) Baseline and quick triage

### Query: data-source breakdown

```spl
index=de_iran_lab
| stats count by event.dataset
| sort - count
```

**Description**
- Shows event volume by dataset (dns, firewall, ot-ics, ddos, etc.).

**How it works**
- `stats count by event.dataset`: groups by dataset and counts each group.
- `sort - count`: largest groups first.

**How to interpret**
- Confirms expected dataset mix and helps detect ingestion gaps.

### Query: lab time window summary

```spl
index=de_iran_lab
| stats earliest(_time) as first latest(_time) as last count
| convert ctime(first) ctime(last)
```

**Description**
- Shows first event time, last event time, and total count.

**How it works**
- `earliest(_time)` / `latest(_time)`: find start and end timestamps.
- `convert ctime(...)`: makes timestamps human readable.

**How to interpret**
- If times look off, fix time picker/ingestion settings before deeper analysis.

---

## 3) Hunt phishing/fraud infrastructure

### 3.1 Query: IOC domain sweep

```spl
index=de_iran_lab (domain="iranforward.org" OR domain="trumpvsirancoin.xyz" OR domain="emiratescryptobank.com" OR domain="emiratesinvestunion.com" OR domain="emirates-post-payments.com")
| table _time event.dataset host.name user.name source.ip destination.ip domain event.action severity message
| sort _time
```

**Description**
- Finds events tied to known suspicious domains.

**How it works**
- Domain filter includes multiple IOC domains using `OR`.
- `table` keeps only useful investigative fields.

**How to interpret**
- Prioritize repeated host/user hits and high-severity actions.

### 3.2 Query: top hosts/users touching suspicious domains

```spl
index=de_iran_lab (domain="iranforward.org" OR domain="trumpvsirancoin.xyz" OR domain="emiratescryptobank.com" OR domain="emiratesinvestunion.com" OR domain="emirates-post-payments.com")
| stats count values(domain) as domains values(event.dataset) as datasets by host.name user.name source.ip
| sort - count
```

**Description**
- Ranks affected entities by IOC activity volume.

**How it works**
- `stats count ... by host.name user.name source.ip`: groups by actor/asset.
- `values(...)`: shows distinct domains and data sources involved.

**How to interpret**
- Highest-count entities are triage priority.

---

## 4) OT/ICS targeting analysis

### 4.1 Query: OT vendor/tooling keywords

```spl
index=de_iran_lab ("FactoryTalk" OR "Allen-Bradley" OR "Rockwell Automation" OR "Unitronics")
| table _time event.dataset host.name user.name source.ip destination.ip event.action event_type severity message
| sort _time
```

**Description**
- Pulls OT-relevant events by platform/vendor keywords.

**How it works**
- Full-text match across event payload for listed terms.

**How to interpret**
- Validate whether activity is inventory-like or suspicious probe behavior.

### 4.2 Query: threat-cluster tags

```spl
index=de_iran_lab ("CL-STA-1128" OR "Cyber Av3ngers" OR "Storm-0784")
| table _time event.dataset host.name user.name source.ip destination.ip event.action event_type severity message
| sort _time
```

**Description**
- Finds events tagged with known threat-cluster references.

**How it works**
- Text search over multiple actor tags.

**How to interpret**
- Treat these as context signals, not standalone proof.

### 4.3 Query: OT dataset pivot

```spl
index=de_iran_lab event.dataset="ot-ics"
| stats count values(event_type) as event_types values(source.ip) as src values(destination.ip) as dst by host.name user.name
| sort - count
```

**Description**
- Summarizes OT activity by host and user.

**How it works**
- Aggregates event types and src/dst IPs into one view per host/user.

**How to interpret**
- Helps identify systems with mixed benign and suspicious OT activity.

---

## 5) DDoS and disruption patterns

### 5.1 Query: DDoS trend by 5-minute window

```spl
index=de_iran_lab event.dataset="ddos" (ddos_spike OR http_flood OR udp_flood OR syn_flood)
| timechart span=5m count by event_type
```

**Description**
- Visualizes disruption patterns over time.

**How it works**
- Filters DDoS event types and buckets into 5-minute intervals.

**How to interpret**
- Spikes indicate probable coordinated activity windows.

### 5.2 Query: top DDoS targets

```spl
index=de_iran_lab event.dataset="ddos" (ddos_spike OR http_flood OR udp_flood OR syn_flood)
| stats count values(event_type) as flood_types by destination.ip destination.port
| sort - count
```

**Description**
- Shows which destinations were most targeted.

**How it works**
- Groups by destination IP/port and counts matching flood events.

**How to interpret**
- High-volume target pairs are your operational hot spots.

---

## 6) Firewall + Palo Alto specific hunt

### Query: verify PAN-OS ingestion

```spl
index=de_iran_lab event.dataset="panw.panos" | stats count
```

**Description**
- Confirms PAN-OS sample logs were ingested.

**How to interpret**
- Expected: 320 events.

### 6.1 Query: suspicious egress in generic firewall dataset

```spl
index=de_iran_lab event.dataset=firewall ("Starlink/VSAT" OR vsat_starlink_egress)
| table _time host.name user.name source.ip destination.ip destination.port domain event.action network.provider severity
| sort _time
```

**Description**
- Finds possible unusual egress paths tied to risk indicators.

**How it works**
- Filters firewall events for provider/event keywords.

**How to interpret**
- Focus on repeated source-destination patterns and high severity.

### 6.2 Query: PAN-OS activity profile

```spl
index=de_iran_lab event.dataset="panw.panos"
| stats count by panw.panos.type panw.panos.subtype panw.panos.rule panw.panos.action
| sort - count
```

**Description**
- Profiles PAN-OS events by type/subtype/rule/action.

**How it works**
- Groups and counts key PAN fields.

**How to interpret**
- Lets students separate normal traffic vs threat events.

### 6.3 Query: high-risk PAN-OS events

```spl
index=de_iran_lab event.dataset="panw.panos" (panw.panos.type="THREAT" OR panw.panos.severity="high" OR panw.panos.severity="critical")
| table _time host.name user.name source.ip destination.ip domain panw.panos.type panw.panos.subtype panw.panos.rule panw.panos.threat.name panw.panos.severity event.action
| sort _time
```

**Description**
- Isolates threat or high-severity PAN-OS events for investigation.

**How it works**
- Keeps records where type is THREAT or severity is high/critical.

**How to interpret**
- These are strong candidates for escalation and timeline inclusion.

---

## 7) Wiper/destructive behavior

### 7.1 Query: wiper behavior sweep

```spl
index=de_iran_lab event.dataset=wiper (wiper_execution OR "SHAMOON-LIKE-WIPER" OR "ZEROCLEAR-LIKE-WIPER" OR "DISK_ERASE_TOOL")
| table _time host.name user.name process.name process.command_line event_type severity message
| sort _time
```

**Description**
- Pulls potential destructive endpoint activity.

**How it works**
- Filters on wiper dataset + behavior/family indicators.

**How to interpret**
- Repeated hosts/users or critical severity should be prioritized.

### 7.2 Query: most affected hosts/users

```spl
index=de_iran_lab event.dataset=wiper (wiper_execution OR "SHAMOON-LIKE-WIPER" OR "ZEROCLEAR-LIKE-WIPER" OR "DISK_ERASE_TOOL")
| stats count values(event_type) as behaviors by host.name user.name
| sort - count
```

**Description**
- Ranks entities by potential destructive activity volume.

**How it works**
- Aggregates behavior types by host and user.

**How to interpret**
- Top rows represent likely impact concentration.

---

## 8) Build full incident timeline in Splunk

### Query: cross-domain timeline

```spl
index=de_iran_lab (domain="iranforward.org" OR domain="trumpvsirancoin.xyz" OR domain="emiratescryptobank.com" OR domain="emiratesinvestunion.com" OR domain="emirates-post-payments.com" OR "FactoryTalk" OR "Allen-Bradley" OR "Rockwell Automation" OR ddos_spike OR wiper_execution OR event.dataset="panw.panos")
| eval indicator=coalesce(domain,event_type,panw.panos.threat.name,event.action)
| table _time event.dataset host.name user.name source.ip destination.ip destination.port indicator event.action event_type severity message
| sort _time
```

**Description**
- Builds a unified timeline across IOC, OT, DDoS, wiper, and PAN-OS signals.

**How it works**
- Broad filter pulls key events.
- `coalesce(...)` creates a single `indicator` field from first non-null value.

**How to interpret**
- Use output to narrate sequence and scope in your report.

Export as CSV for submission.

---

## 9) Create detections in SPL

### Detection 1: phishing/fraud domains

```spl
index=de_iran_lab (domain="iranforward.org" OR domain="trumpvsirancoin.xyz" OR domain="emiratescryptobank.com" OR domain="emiratesinvestunion.com" OR domain="emirates-post-payments.com")
| stats count values(domain) as domains by host.name user.name source.ip
```

**Purpose**
- IOC detection for known suspicious domains.

**How it works**
- Aggregates IOC hits by host/user/source.

### Detection 2: OT/ICS targeting terms

```spl
index=de_iran_lab event.dataset="ot-ics" ("FactoryTalk" OR "Allen-Bradley" OR "Rockwell Automation" OR "Unitronics")
| stats count values(event_type) as event_types by source.ip destination.ip host.name
```

**Purpose**
- Behavior-focused OT detection starter.

**How it works**
- Searches OT dataset for high-value terms and summarizes paths.

### Detection 3: DDoS spike behavior

```spl
index=de_iran_lab event.dataset="ddos" (ddos_spike OR http_flood OR udp_flood OR syn_flood)
| bucket _time span=5m
| stats count by _time destination.ip event_type
| where count > 10
```

**Purpose**
- Detects unusual DDoS volume bursts.

**How it works**
- Buckets into 5-minute windows and flags counts > 10.

### Detection 4: Palo Alto high-risk threat events

```spl
index=de_iran_lab event.dataset="panw.panos" panw.panos.type="THREAT" (panw.panos.severity="high" OR panw.panos.severity="critical")
| stats count values(panw.panos.threat.name) as threats by host.name source.ip destination.ip domain panw.panos.rule
```

**Purpose**
- Prioritizes high-confidence PAN-OS threat events.

**How it works**
- Restricts to THREAT + high/critical severity, then summarizes.

### Detection 5: destructive endpoint behavior

```spl
index=de_iran_lab event.dataset=wiper (wiper_execution OR "SHAMOON-LIKE-WIPER" OR "ZEROCLEAR-LIKE-WIPER" OR "DISK_ERASE_TOOL")
| stats count values(process.command_line) as cmds by host.name user.name
```

**Purpose**
- Detects possible destructive behavior by host/user.

**How it works**
- Aggregates wiper indicators and command lines for triage.

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

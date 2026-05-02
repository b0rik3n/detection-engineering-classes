# Student Click-by-Click Guide

Lab: `iran-cyber-risk-escalation-20260430-2055`

Source article:
- Unit 42 Threat Brief: Escalation of Cyber Risk Related to Iran (Updated April 17)
- https://unit42.paloaltonetworks.com/iranian-cyberattacks-2026/

Scenario: After regional conflict escalation and internet restoration, defenders observe phishing/fraud domains, OT/ICS targeting, Starlink/VSAT egress patterns, DDoS disruption, and wiper-like activity.

---

## 0. What you are trying to answer

By the end of this lab, you should be able to answer:

1. Which domains and IPs indicate Iran-related phishing or fraud activity?
2. Which hosts/services show OT/ICS reconnaissance behavior?
3. Where do DDoS and disruption patterns appear?
4. Which hosts show potential destructive behavior (`wiper_execution`)?
5. What detections should be deployed for future coverage?

High-value terms:

- `CL-STA-1128`
- `Cyber Av3ngers`
- `Storm-0784`
- `FactoryTalk`
- `Allen-Bradley`
- `Rockwell Automation`
- `iranforward.org`
- `trumpvsirancoin.xyz`
- `emiratescryptobank.com`
- `emiratesinvestunion.com`
- `emirates-post-payments.com`
- `Starlink/VSAT`
- `ddos_spike`
- `wiper_execution`

---

## 1. Load the data in Mucaro Scout

### 1.1 Open Scout

1. Open browser.
2. Go to Scout URL from instructor (commonly `http://localhost:5173`).
3. Confirm **Guided Search** is visible.

### 1.2 Upload combined dataset

1. Click **Upload data**.
2. Select:

```text
labs/iran-cyber-risk-escalation-20260430-2055/data/combined.jsonl
```

3. Click **Upload & index**.
4. Wait for success notification.

Expected: ~700 events indexed.

### 1.3 Optional source-by-source upload

If requested by instructor, upload individually in this order:

1. `threat-intel.jsonl`
2. `email.jsonl`
3. `dns.jsonl`
4. `firewall.jsonl`
5. `paloalto-firewall.jsonl`
6. `ot-ics.jsonl`
7. `ddos.jsonl`
8. `wiper.jsonl`

---

## 2. Identify phishing and fraud infrastructure

### 2.1 Search known suspicious domains

Run each query:

```text
iranforward.org
```

```text
trumpvsirancoin.xyz
```

```text
emiratescryptobank.com OR emiratesinvestunion.com OR emirates-post-payments.com
```

Record for each:

- first timestamp
- host.name
- user.name
- source.ip / destination.ip
- event.dataset

### 2.2 Pivot into DNS and firewall evidence

Query:

```text
event.dataset:dns AND (iranforward.org OR trumpvsirancoin.xyz OR emiratescryptobank.com OR emiratesinvestunion.com OR emirates-post-payments.com)
```

Then:

```text
event.dataset:firewall AND (iranforward.org OR trumpvsirancoin.xyz OR emiratescryptobank.com OR emiratesinvestunion.com OR emirates-post-payments.com)
```

Answer:

- Which domains were resolved versus blocked/allowed?
- Which hosts repeatedly interacted with suspicious domains?

---

## 3. Scope OT/ICS targeting behavior

### 3.1 Search OT/ICS tool and vendor terms

Run queries:

```text
FactoryTalk OR "Allen-Bradley" OR "Rockwell Automation" OR Unitronics
```

```text
CL-STA-1128 OR "Cyber Av3ngers" OR Storm-0784
```

### 3.2 Filter to OT/ICS dataset

Query:

```text
event.dataset:"ot-ics" AND (FactoryTalk OR "Allen-Bradley" OR "Rockwell Automation" OR Unitronics)
```

Record:

- targeted service/asset
- source and destination IPs
- event types
- severity

---

## 4. Detect disruption and infrastructure anomalies

### 4.1 Hunt DDoS patterns

Query:

```text
ddos_spike OR http_flood OR udp_flood OR syn_flood
```

Then isolate:

```text
event.dataset:ddos
```

Record:

- targeted host/service
- flood type
- peak windows

### 4.2 Hunt unusual egress signals

Query:

```text
"Starlink/VSAT" OR vsat_starlink_egress
```

Then in Palo Alto logs:

```text
event.dataset:"panw.panos" AND ("Starlink/VSAT" OR panw.panos.threat.name:* OR panw.panos.rule:untrust-blocklist)
```

Answer:

- Which firewall events indicate potential risky egress paths?
- Are the same hosts tied to phishing or OT activity?

---

## 5. Detect destructive activity indicators

### 5.1 Search for wiper behavior

Query:

```text
wiper_execution OR SHAMOON-LIKE-WIPER OR ZEROCLEAR-LIKE-WIPER OR DISK_ERASE_TOOL
```

Then isolate endpoint evidence:

```text
event.dataset:wiper
```

Record:

- host.name
- user.name
- process / command evidence
- timestamp of first execution

### 5.2 Correlate with preceding activity

Query timeline set:

```text
(iranforward.org OR trumpvsirancoin.xyz OR emiratescryptobank.com OR FactoryTalk OR ddos_spike OR wiper_execution)
```

Sort by time ascending.

Expected chain:

```text
threat intel signal -> phishing/fraud infra -> network/OT probing -> disruption attempts -> destructive behavior
```

---

## 6. Build the incident timeline

Create a table in notes:

```text
Time | Dataset | Host | User | Indicator | Event | Why it matters
```

Minimum timeline milestones:

1. first phishing domain observation
2. first OT/ICS targeting observation
3. first DDoS spike
4. first VSAT/Starlink-related indicator
5. first wiper execution event

---

## 7. Write detections

Create at least 5 detections.

### 7.1 Phishing domain detection (IOC)

```text
domain IN (iranforward.org, trumpvsirancoin.xyz, emiratescryptobank.com, emiratesinvestunion.com, emirates-post-payments.com)
```

### 7.2 OT/ICS targeting detection (behavior)

```text
event.dataset:"ot-ics" AND (FactoryTalk OR "Allen-Bradley" OR "Rockwell Automation" OR Unitronics)
```

### 7.3 DDoS disruption detection

```text
event.dataset:ddos AND (ddos_spike OR http_flood OR udp_flood OR syn_flood)
```

### 7.4 Suspicious egress path detection

```text
event.dataset:firewall AND ("Starlink/VSAT" OR vsat_starlink_egress)
```

### 7.5 Destructive behavior detection

```text
event.dataset:wiper AND (wiper_execution OR SHAMOON-LIKE-WIPER OR ZEROCLEAR-LIKE-WIPER OR DISK_ERASE_TOOL)
```

For each detection include:

- query
- what it catches
- likely false positives
- one tuning improvement

---

## 8. Splunk path (click-by-click)

1. Open **Search & Reporting**.
2. Set time range to **All time**.
3. Run this broad triage search:

```spl
index=* ("iranforward.org" OR "trumpvsirancoin.xyz" OR "emiratescryptobank.com" OR "FactoryTalk" OR "ddos_spike" OR "wiper_execution")
| table _time event.dataset host.name user.name source.ip destination.ip domain event.action event_type severity message
| sort _time
```

4. Run OT/ICS-specific search:

```spl
index=* event.dataset="ot-ics" ("FactoryTalk" OR "Allen-Bradley" OR "Rockwell Automation" OR "Unitronics")
| stats count values(event_type) as event_types values(source.ip) as src values(destination.ip) as dst by host.name user.name
```

5. Run wiper search:

```spl
index=* event.dataset=wiper (wiper_execution OR "SHAMOON-LIKE-WIPER" OR "ZEROCLEAR-LIKE-WIPER" OR "DISK_ERASE_TOOL")
| table _time host.name user.name process.name process.command_line severity
```

---

## 9. Elastic/OpenSearch path (click-by-click)

1. Open **Discover**.
2. Select lab index/data view.
3. Set time range to cover lab period or **All time**.
4. Search:

```text
iranforward.org OR trumpvsirancoin.xyz OR emiratescryptobank.com OR FactoryTalk OR ddos_spike OR wiper_execution
```

5. Add columns:

- `@timestamp`
- `event.dataset`
- `host.name`
- `user.name`
- `source.ip`
- `destination.ip`
- `domain`
- `event.action`
- `event_type`
- `severity`

6. Optional ES|QL timeline:

```esql
FROM *
| WHERE domain IN ("iranforward.org","trumpvsirancoin.xyz","emiratescryptobank.com","emiratesinvestunion.com","emirates-post-payments.com")
   OR event_type IN ("ddos_spike","wiper_execution")
   OR message LIKE "*FactoryTalk*"
| KEEP @timestamp, event.dataset, host.name, user.name, source.ip, destination.ip, domain, event.action, event_type, severity, message
| SORT @timestamp ASC
```

---

## 10. Final deliverable format

Submit a short report with:

1. **Executive summary** (3-5 sentences)
2. **Affected hosts/users/services**
3. **Indicators and behaviors observed**
4. **Timeline**
5. **At least 5 detections** (with tuning notes)
6. **Response recommendations** (prioritized)

Suggested response actions:

- block suspicious domains and IPs
- isolate likely impacted hosts
- validate OT network segmentation
- increase DDoS protections and rate limits
- run destructive-activity hunt across all endpoints

---

## 11. Grading checklist

- [ ] identified phishing/fraud infrastructure
- [ ] identified OT/ICS targeting evidence
- [ ] identified DDoS/disruption evidence
- [ ] identified potential wiper activity
- [ ] built a coherent cross-source timeline
- [ ] wrote at least 5 detections (IOC + behavior)
- [ ] included practical response recommendations

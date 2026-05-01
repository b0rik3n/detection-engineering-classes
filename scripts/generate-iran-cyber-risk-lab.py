#!/usr/bin/env python3
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = "iran-cyber-risk-escalation-20260430-2055"
OUT = ROOT / "labs" / LAB
DATA = OUT / "data"
START = datetime(2026, 4, 17, 9, 0, tzinfo=timezone.utc)
random.seed(4242)

ACTORS = ["CL-STA-1128", "Cyber Av3ngers", "Storm-0784"]
PHISH_DOMAINS = [
    "iranforward.org",
    "trumpvsirancoin.xyz",
    "emiratescryptobank.com",
    "emiratesinvestunion.com",
    "emirates-post-payments.com",
    "saudi-erp-login.com",
]
OT_TARGETS = ["FactoryTalk", "Allen-Bradley", "Rockwell Automation", "Unitronics PLC"]
OT_PORTS = [44818, 2222, 502, 789, 8080]
WIPER_NAMES = ["SHAMOON-LIKE-WIPER", "ZEROCLEAR-LIKE-WIPER", "DISK_ERASE_TOOL"]
DDOS_TOOLS = ["http_flood", "udp_flood", "syn_flood"]
BAD_IPS = ["185.225.74.112", "45.83.64.106", "91.219.236.42", "193.32.162.77"]
BENIGN_IPS = ["13.107.246.45", "104.16.132.229", "140.82.114.4", "142.250.72.14"]
HOSTS = ["erp-win-01", "vpn-edge-02", "plc-eng-03", "scada-hmi-04", "mail-gw-05", "finance-win-06", "web-prod-07", "soc-sensor-08"]
USERS = ["alice", "bob", "carol", "dlee", "evan", "fatima", "noura", "sam", "svc-scada", "svc-erp"]


def ts(i: int, offset: int = 0) -> str:
    return (START + timedelta(minutes=i, seconds=(i * 19 + offset) % 60)).isoformat().replace("+00:00", "Z")


def suspicious(i: int) -> bool:
    return i in {6, 7, 8, 19, 20, 21, 38, 39, 52, 53, 67, 68, 84, 85, 96, 97}


def host_user(i: int) -> tuple[str, str]:
    return HOSTS[i % len(HOSTS)], USERS[i % len(USERS)]


def write_jsonl(path: Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, separators=(",", ":")) + "\n")


def base(source: str, i: int, action: str, severity: str, message: str) -> dict:
    host, user = host_user(i)
    return {
        "@timestamp": ts(i),
        "event.dataset": source,
        "event.category": category(source),
        "event.action": action,
        "event_type": action,
        "host.name": host,
        "user.name": user,
        "severity": severity,
        "lab.name": LAB,
        "scenario.name": "Iran-related cyber risk escalation after regional conflict and internet restoration",
        "message": message,
    }


def category(source: str) -> str:
    if source in {"dns", "proxy", "firewall", "ddos", "xpanse"}:
        return "network"
    if source in {"email", "identity"}:
        return "authentication"
    if source in {"endpoint", "wiper"}:
        return "process"
    if source == "ot-ics":
        return "industrial_control"
    return "threat_intel"


def threat_intel_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        action = "iran_risk_indicator" if bad else "intel_observation"
        indicator = random.choice(PHISH_DOMAINS + ACTORS + OT_TARGETS + WIPER_NAMES) if bad else "regional monitoring note"
        e = base("threat-intel", i, action, "high" if bad else "info", f"Threat intel observation: {indicator}")
        e.update({
            "threat.actor": random.choice(ACTORS) if bad else "",
            "threat.campaign": "Iran cyber risk escalation 2026" if bad else "",
            "indicator.value": indicator,
            "article.source": "Unit 42 Threat Brief: Escalation of Cyber Risk Related to Iran",
            "article.date": "2026-04-17",
        })
        events.append(e)
    return events


def phishing_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        domain = random.choice(PHISH_DOMAINS) if bad else random.choice(["microsoft.com", "google.com", "office.com", "example.org"])
        lure = random.choice(["conflict_donation", "crypto_scam", "emirates_bank_impersonation", "erp_login_phish", "package_payment_fraud"])
        action = lure if bad else "benign_email"
        e = base("email", i + 1, action, "high" if bad else "info", f"Email lure observed for {domain}" if bad else "Routine business email")
        e.update({
            "email.subject": "Urgent regional payment portal update" if bad else "Project update",
            "url.full": f"https://{domain}/login/{1000+i}" if bad else f"https://{domain}/",
            "domain": domain,
            "source.ip": random.choice(BAD_IPS) if bad else random.choice(BENIGN_IPS),
            "phishing.theme": lure if bad else "",
            "threat.actor": random.choice(ACTORS) if bad and i % 3 == 0 else "",
        })
        events.append(e)
    return events


def dns_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        domain = random.choice(PHISH_DOMAINS) if bad else random.choice(["cloudflare-dns.com", "ubuntu.com", "github.com", "office.com"])
        action = "dns_query"
        e = base("dns", i + 2, action, "medium" if bad else "info", f"DNS query for {domain}")
        e.update({
            "domain": domain,
            "dns.question.name": domain,
            "destination.ip": random.choice(BAD_IPS) if bad else random.choice(BENIGN_IPS),
            "dns.answers": [random.choice(BAD_IPS) if bad else random.choice(BENIGN_IPS)],
        })
        events.append(e)
    return events


def ot_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        target = random.choice(OT_TARGETS) if bad else random.choice(["HMI", "Historian", "Engineering Workstation"])
        action = "factorytalk_scan" if bad and target == "FactoryTalk" else ("allen_bradley_plc_probe" if bad else "asset_inventory")
        port = random.choice(OT_PORTS) if bad else random.choice([80, 443, 3389])
        e = base("ot-ics", i + 3, action, "critical" if bad else "info", f"OT/ICS service activity involving {target}")
        e.update({
            "ot.vendor": "Rockwell Automation" if bad else "",
            "ot.product": target,
            "threat.actor": random.choice(ACTORS) if bad else "",
            "source.ip": random.choice(BAD_IPS) if bad else f"10.77.{i%4}.{20+i%200}",
            "destination.ip": f"10.77.4.{10+i%30}",
            "destination.port": port,
            "service.name": "FactoryTalk" if port in {44818, 2222} else ("modbus" if port == 502 else "unknown"),
        })
        events.append(e)
    return events


def firewall_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        action = "vsat_starlink_egress" if bad and i % 2 else ("blocked_phishing_domain" if bad else "allowed")
        e = base("firewall", i + 4, action, "high" if bad else "info", "Network control matched Iran-related risk indicator" if bad else "Routine firewall event")
        e.update({
            "source.ip": random.choice(BAD_IPS) if bad else f"10.20.{i%8}.{20+i%180}",
            "destination.ip": random.choice(BAD_IPS if bad else BENIGN_IPS),
            "destination.port": random.choice([443, 8443, 8080, 44818]) if bad else random.choice([80, 443, 53]),
            "domain": random.choice(PHISH_DOMAINS) if bad else "",
            "network.transport": "tcp",
            "network.bytes": 500000 + i if bad else 1200 + i,
            "network.provider": "Starlink/VSAT" if action == "vsat_starlink_egress" else "",
        })
        events.append(e)
    return events


def ddos_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        tool = random.choice(DDOS_TOOLS) if bad else "normal_traffic"
        action = "ddos_spike" if bad else "traffic_baseline"
        e = base("ddos", i + 5, action, "high" if bad else "info", f"Traffic pattern: {tool}")
        e.update({
            "ddos.tool": tool,
            "target.service": random.choice(["public_website", "vpn_gateway", "payment_portal"]),
            "source.geo.country_iso_code": "IR" if bad else random.choice(["US", "AE", "SA"]),
            "requests.per_second": 80000 + i * 10 if bad else 200 + i,
            "threat.actor": "hacktivist_proxy" if bad else "",
        })
        events.append(e)
    return events


def wiper_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        wiper = random.choice(WIPER_NAMES) if bad else "benign_admin_tool"
        action = "wiper_execution" if bad else "process_start"
        e = base("wiper", i + 6, action, "critical" if bad else "info", f"Endpoint process activity: {wiper}")
        e.update({
            "process.name": "diskwipe.exe" if bad else random.choice(["powershell.exe", "cmd.exe", "backup.exe"]),
            "process.command_line": f"diskwipe.exe /wipe /target=C: /campaign=iran-risk" if bad else "backup.exe --check",
            "malware.family": wiper if bad else "",
            "file.path": f"C:\\ProgramData\\{wiper.lower()}\\diskwipe.exe" if bad else "",
            "threat.actor": random.choice(ACTORS) if bad and i % 3 == 0 else "",
        })
        events.append(e)
    return events


def write_docs() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "README.md").write_text(f"""# de-lab-{LAB}

Detection engineering lab based on Unit 42's **Threat Brief: Escalation of Cyber Risk Related to Iran (Updated April 17)**.

Timestamped class name: `{LAB}`

## Scenario

After regional military escalation and a 47-day near-complete Iranian internet outage, defenders observe renewed cyber risk related to Iran-aligned activity. The lab includes synthetic telemetry for conflict-themed phishing and fraud, hacktivist DDoS, possible VSAT/Starlink egress, destructive/wiper behavior, and OT/ICS targeting of Rockwell Automation / Allen-Bradley / FactoryTalk-style services by CL-STA-1128 / Cyber Av3ngers / Storm-0784.

## Known indicators and behaviors

- Threat cluster names: `CL-STA-1128`, `Cyber Av3ngers`, `Storm-0784`
- Phishing/fraud domains: `{', '.join(PHISH_DOMAINS)}`
- OT/ICS targets: `{', '.join(OT_TARGETS)}`
- DDoS behaviors: `{', '.join(DDOS_TOOLS)}`
- Wiper families: `{', '.join(WIPER_NAMES)}`
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
""", encoding="utf-8")

    (DATA / "README.md").write_text(f"""# Iran cyber risk escalation data pack

Files:

- `threat-intel.jsonl` - 100 intelligence observations
- `email.jsonl` - 100 phishing/social lure events
- `dns.jsonl` - 100 DNS events
- `ot-ics.jsonl` - 100 OT/ICS service and PLC-oriented events
- `firewall.jsonl` - 100 network control events
- `ddos.jsonl` - 100 DDoS/traffic events
- `wiper.jsonl` - 100 endpoint destructive activity events
- `combined.jsonl` - 700 merged events sorted by timestamp

Known search terms:

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
- `Starlink/VSAT`
- `ddos_spike`
- `wiper_execution`
""", encoding="utf-8")

    (OUT / "exercise").mkdir(exist_ok=True)
    (OUT / "exercise" / "README.md").write_text("""# Student exercise

## Task 1: Identify conflict-themed phishing
Search for suspicious domains including `iranforward.org`, `trumpvsirancoin.xyz`, `emiratescryptobank.com`, and `emiratesinvestunion.com`.

## Task 2: Scope OT/ICS targeting
Search `FactoryTalk`, `Allen-Bradley`, `Rockwell Automation`, `CL-STA-1128`, and `Cyber Av3ngers`.

## Task 3: Identify disruption patterns
Search for `ddos_spike`, `Starlink/VSAT`, and `wiper_execution`.

## Task 4: Build an incident timeline
Correlate threat intel, phishing, DNS, firewall, OT/ICS, DDoS, and wiper telemetry.

## Task 5: Write detections
Create detections for phishing domains, OT/ICS scanning, DDoS spikes, and wiper execution.

## Deliverable
Submit a short report with affected hosts/services, indicators, timeline, detections, false-positive notes, and response recommendations.
""", encoding="utf-8")

    (OUT / "splunk").mkdir(exist_ok=True)
    (OUT / "splunk" / "starter-searches.spl").write_text("""index=* ("CL-STA-1128" OR "Cyber Av3ngers" OR "Storm-0784" OR "FactoryTalk" OR "Allen-Bradley")
| table _time event.dataset host.name user.name event_type threat.actor ot.product service.name destination.port severity message

index=* (domain=iranforward.org OR domain=trumpvsirancoin.xyz OR domain=emiratescryptobank.com OR domain=emiratesinvestunion.com)
| table _time event.dataset host.name user.name domain url.full phishing.theme severity message

index=* (event_type=ddos_spike OR event_type=wiper_execution OR network.provider="Starlink/VSAT")
| table _time event.dataset host.name event_type source.ip destination.ip requests.per_second malware.family severity message
""", encoding="utf-8")

    (OUT / "elastic" / "esql").mkdir(parents=True, exist_ok=True)
    (OUT / "elastic" / "esql" / "starter-queries.esql").write_text("""FROM logs-*
| WHERE threat.actor IN ("CL-STA-1128", "Cyber Av3ngers", "Storm-0784") OR ot.product IN ("FactoryTalk", "Allen-Bradley", "Rockwell Automation")
| KEEP @timestamp, event.dataset, host.name, user.name, event_type, threat.actor, ot.product, service.name, destination.port, severity, message
| SORT @timestamp ASC

FROM logs-*
| WHERE domain IN ("iranforward.org", "trumpvsirancoin.xyz", "emiratescryptobank.com", "emiratesinvestunion.com")
| KEEP @timestamp, event.dataset, host.name, user.name, domain, url.full, phishing.theme, severity, message

FROM logs-*
| WHERE event_type IN ("ddos_spike", "wiper_execution", "vsat_starlink_egress")
| KEEP @timestamp, event.dataset, host.name, event_type, source.ip, destination.ip, requests.per_second, malware.family, network.provider, severity, message
""", encoding="utf-8")

    (OUT / "kibana").mkdir(exist_ok=True)
    (OUT / "kibana" / "checklist.md").write_text("""# Kibana / Discover checklist

- Create/select the lab data view.
- Set time range to All time.
- Search phishing/fraud domains.
- Search OT terms: FactoryTalk, Allen-Bradley, Rockwell Automation.
- Search disruption terms: ddos_spike, wiper_execution, Starlink/VSAT.
- Build a timeline and save at least one detection/rule query.
""", encoding="utf-8")

    (OUT / "instructor").mkdir(exist_ok=True)
    (OUT / "instructor" / "answer-key.md").write_text(f"""# Instructor answer key

## Core story

The lab models the defensive implications of Unit 42's Iran cyber risk brief: conflict-themed phishing/fraud, hacktivist disruption, OT/ICS targeting, and destructive/wiper risk.

## Must-find indicators

- `CL-STA-1128`, `Cyber Av3ngers`, `Storm-0784`
- `FactoryTalk`, `Allen-Bradley`, `Rockwell Automation`
- `iranforward.org`, `trumpvsirancoin.xyz`, `emiratescryptobank.com`, `emiratesinvestunion.com`
- `Starlink/VSAT`
- `ddos_spike`
- `wiper_execution`

## Good student outcomes

- Separates phishing/fraud, OT targeting, DDoS, and wiper activity into distinct detection classes
- Builds a timeline across multiple source types
- Notes that generated lab domains/events are synthetic and article-inspired
- Includes false-positive handling for OT inventory scans and high-volume benign traffic
""", encoding="utf-8")


def main() -> None:
    datasets = {
        "threat-intel.jsonl": threat_intel_events(),
        "email.jsonl": phishing_events(),
        "dns.jsonl": dns_events(),
        "ot-ics.jsonl": ot_events(),
        "firewall.jsonl": firewall_events(),
        "ddos.jsonl": ddos_events(),
        "wiper.jsonl": wiper_events(),
    }
    combined = []
    for name, events in datasets.items():
        write_jsonl(DATA / name, events)
        combined.extend(events)
    combined.sort(key=lambda e: e["@timestamp"])
    write_jsonl(DATA / "combined.jsonl", combined)
    write_docs()
    for name, events in datasets.items():
        print(f"{name}: {len(events)}")
    print(f"combined.jsonl: {len(combined)}")


if __name__ == "__main__":
    main()

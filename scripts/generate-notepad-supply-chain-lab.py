#!/usr/bin/env python3
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
LAB = "notepad-plus-plus-supply-chain-20260430-2101"
OUT = ROOT / "labs" / LAB
DATA = OUT / "data"
START = datetime(2025, 9, 12, 8, 0, tzinfo=timezone.utc)
random.seed(8911)

ACTOR = "Lotus Blossom"
APP = "Notepad++"
UPDATER = "GUP.exe"
WINGUP = "WinGUp"
MUTEX = "Global\\Jdhfv_1.0.1"
C2_IPS = ["45.76.155.202", "45.77.31.210", "45.32.144.255"]
UPDATE_URLS = ["http://45.76.155.202/update/update.exe", "http://45.32.144.255/update/update.exe"]
MALWARE = ["Chrysalis", "Cobalt Strike Beacon"]
SIDELOAD_PROC = "BluetoothService.exe"
SIDELOAD_DLL = "log.dll"
LUA_API = "EnumWindowStationsW"
SECTORS = ["government", "telecommunications", "critical_infrastructure", "energy", "financial", "manufacturing", "software_development", "cloud_hosting"]
REGIONS = ["Southeast Asia", "South America", "United States", "Europe"]
HOSTS = ["jumpbox-01", "admin-win-02", "telco-noc-03", "gov-sec-04", "energy-eng-05", "cloud-admin-06", "manufacturing-hmi-07", "devops-win-08"]
USERS = ["alice", "bob", "carol", "dlee", "evan", "frank", "grace", "heidi", "svc-admin", "neteng"]
BENIGN_IPS = ["13.107.246.45", "104.16.132.229", "140.82.114.4", "151.101.0.223"]


def ts(i: int, offset: int = 0) -> str:
    return (START + timedelta(minutes=i, seconds=(i * 13 + offset) % 60)).isoformat().replace("+00:00", "Z")


def suspicious(i: int) -> bool:
    return i in {5, 6, 7, 16, 17, 30, 31, 47, 48, 62, 63, 79, 80, 92, 93, 97}


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
        "scenario.name": "Notepad++ updater infrastructure compromise and supply-chain infection",
        "message": message,
    }


def category(source: str) -> str:
    if source in {"dns", "proxy", "firewall"}:
        return "network"
    if source in {"endpoint", "module-load", "mutex", "installer"}:
        return "process"
    if source == "threat-intel":
        return "threat_intel"
    return "host"


def threat_intel_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        indicator = random.choice([ACTOR, APP, WINGUP, "DLL sideloading", "Supply chain", "Chrysalis", "Cobalt Strike", *C2_IPS]) if bad else "software update telemetry baseline"
        e = base("threat-intel", i, "supply_chain_indicator" if bad else "intel_observation", "high" if bad else "info", f"Threat intel observation: {indicator}")
        e.update({
            "threat.actor": ACTOR if bad else "",
            "indicator.value": indicator,
            "target.application": APP if bad else "",
            "target.sector": random.choice(SECTORS) if bad else "",
            "target.region": random.choice(REGIONS) if bad else "",
            "article.source": "Unit 42 Nation-State Actors Exploit Notepad++ Supply Chain",
            "article.date": "2026-02-11",
        })
        events.append(e)
    return events


def update_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        host, user = host_user(i + 1)
        action = "malicious_update_manifest" if bad else "legitimate_update_check"
        url = random.choice(UPDATE_URLS) if bad else "https://notepad-plus-plus.org/update/getDownloadUrl.php"
        e = base("updater", i + 1, action, "high" if bad else "info", "Targeted Notepad++ updater request redirected to malicious installer" if bad else "Normal Notepad++ update check")
        e.update({
            "host.name": host,
            "user.name": user,
            "process.name": UPDATER,
            "process.command_line": f"{UPDATER} -i{url}",
            "application.name": APP,
            "updater.name": WINGUP,
            "url.full": url,
            "destination.ip": random.choice(C2_IPS) if bad else random.choice(BENIGN_IPS),
            "file.name": "update.exe" if bad else "npp.installer.x64.exe",
            "threat.actor": ACTOR if bad else "",
        })
        events.append(e)
    return events


def proxy_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        url = random.choice(UPDATE_URLS) if bad else random.choice(["https://notepad-plus-plus.org/", "https://github.com/", "https://wingup.org/"])
        action = "malicious_update_download" if bad else "http_request"
        e = base("proxy", i + 2, action, "high" if bad else "info", f"HTTP request to {url}")
        e.update({
            "url.full": url,
            "domain": "" if bad else url.split('/')[2],
            "destination.ip": random.choice(C2_IPS) if bad else random.choice(BENIGN_IPS),
            "http.request.method": "GET",
            "http.response.status_code": 200,
            "file.name": "update.exe" if bad else "",
            "threat.actor": ACTOR if bad else "",
        })
        events.append(e)
    return events


def endpoint_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        variant = "lua" if i % 2 == 0 else "dll_sideload"
        action = "lua_script_injection" if bad and variant == "lua" else ("dll_sideload_execution" if bad else "process_start")
        proc = "update.exe" if bad and variant == "lua" else (SIDELOAD_PROC if bad else random.choice(["notepad++.exe", "powershell.exe", "cmd.exe"]))
        cmd = f"update.exe --run-lua --api {LUA_API} --payload cobaltstrike" if bad and variant == "lua" else (f"{SIDELOAD_PROC} --load {SIDELOAD_DLL}" if bad else f"{proc} normal activity")
        e = base("endpoint", i + 3, action, "critical" if bad else "info", "Notepad++ supply-chain infection behavior observed" if bad else "Routine endpoint process")
        e.update({
            "process.name": proc,
            "process.command_line": cmd,
            "process.parent.name": UPDATER if bad else "explorer.exe",
            "file.name": "update.exe" if bad and variant == "lua" else SIDELOAD_DLL if bad else "",
            "attack.technique": "DLL Sideloading" if bad and variant == "dll_sideload" else ("Lua script injection" if bad else ""),
            "api.name": LUA_API if bad and variant == "lua" else "",
            "malware.family": "Cobalt Strike Beacon" if bad and variant == "lua" else ("Chrysalis" if bad else ""),
            "threat.actor": ACTOR if bad else "",
        })
        events.append(e)
    return events


def module_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        action = "load_image" if bad else "module_load"
        e = base("module-load", i + 4, action, "critical" if bad else "info", "Renamed Bitdefender component loaded suspicious log.dll" if bad else "Normal module load")
        e.update({
            "actor_process_signature_vendor": "Bitdefender SRL" if bad else "Microsoft Corporation",
            "actor_process_signature_product": "Bitdefender Endpoint Security Tools" if bad else "Windows",
            "actor_process_image_name": SIDELOAD_PROC if bad else "svchost.exe",
            "actor_process_image_path": f"C:\\Users\\Public\\{SIDELOAD_PROC}" if bad else "C:\\Windows\\System32\\svchost.exe",
            "action_module_path": f"C:\\Users\\Public\\{SIDELOAD_DLL}" if bad else "C:\\Windows\\System32\\kernel32.dll",
            "file.name": SIDELOAD_DLL if bad else "kernel32.dll",
            "malware.family": "Chrysalis" if bad else "",
            "threat.actor": ACTOR if bad else "",
        })
        events.append(e)
    return events


def mutex_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        action = "chrysalis_mutex_created" if bad else "mutex_created"
        e = base("mutex", i + 5, action, "critical" if bad else "info", "Chrysalis mutex observed" if bad else "Routine mutex creation")
        e.update({
            "mutex.name": MUTEX if bad else f"Global\\Normal_{i}",
            "process.name": "BluetoothService.exe" if bad else random.choice(["chrome.exe", "notepad++.exe", "explorer.exe"]),
            "malware.family": "Chrysalis" if bad else "",
            "threat.actor": ACTOR if bad else "",
        })
        events.append(e)
    return events


def firewall_events() -> list[dict]:
    events = []
    for i in range(100):
        bad = suspicious(i)
        action = "c2_beacon" if bad else "allowed"
        dst = random.choice(C2_IPS) if bad else random.choice(BENIGN_IPS)
        e = base("firewall", i + 6, action, "high" if bad else "info", f"Outbound connection to {dst}")
        e.update({
            "source.ip": f"10.20.{i % 8}.{20 + i % 180}",
            "destination.ip": dst,
            "destination.port": random.choice([80, 443, 8443]) if bad else random.choice([80, 443, 53]),
            "network.transport": "tcp",
            "network.bytes": 82000 + i if bad else 1800 + i,
            "malware.family": random.choice(MALWARE) if bad else "",
            "threat.actor": ACTOR if bad else "",
        })
        events.append(e)
    return events


def write_docs() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "README.md").write_text(f"""# de-lab-{LAB}

Detection engineering lab based on Unit 42's **Nation-State Actors Exploit Notepad++ Supply Chain**.

Timestamped class name: `{LAB}`

## Scenario

Between June and December 2025, attackers associated with `Lotus Blossom` compromised infrastructure used by the `Notepad++` updater ecosystem. Targeted users received malicious update manifests and downloaded `update.exe`. Two infection chains are represented in this lab: a Lua script injection variant leading to `Cobalt Strike Beacon`, and DLL sideloading using a renamed Bitdefender component, `BluetoothService.exe`, to load `log.dll` and execute the `Chrysalis` backdoor.

## Known indicators and behaviors

- Threat actor: `Lotus Blossom`
- Application: `Notepad++`
- Updater: `WinGUp`, `GUP.exe`
- Malicious installer: `update.exe`
- C2/download IPs: `{', '.join(C2_IPS)}`
- Download URLs: `{', '.join(UPDATE_URLS)}`
- DLL sideloading: `{SIDELOAD_PROC}` loads `{SIDELOAD_DLL}`
- Malware: `Chrysalis`, `Cobalt Strike Beacon`
- Mutex: `{MUTEX}`
- Lua API marker: `{LUA_API}`

## Structure

- `data/` source-separated synthetic logs
- `exercise/` student workflow
- `splunk/` starter searches
- `elastic/esql/` starter queries
- `kibana/` checklist
- `instructor/` answer key
""", encoding="utf-8")

    (DATA / "README.md").write_text(f"""# Notepad++ supply-chain data pack

Files:

- `threat-intel.jsonl` - 100 intelligence observations
- `updater.jsonl` - 100 Notepad++ updater events
- `proxy.jsonl` - 100 HTTP download events
- `endpoint.jsonl` - 100 process execution events
- `module-load.jsonl` - 100 DLL/module load events
- `mutex.jsonl` - 100 mutex/system-call style events
- `firewall.jsonl` - 100 outbound C2 events
- `combined.jsonl` - 700 events merged and sorted by timestamp

Known search terms:

- `Lotus Blossom`
- `Notepad++`
- `WinGUp`
- `GUP.exe`
- `update.exe`
- `45.76.155.202`
- `45.77.31.210`
- `45.32.144.255`
- `45.76.155.202/update/update.exe`
- `45.32.144.255/update/update.exe`
- `BluetoothService.exe`
- `log.dll`
- `Chrysalis`
- `Cobalt Strike Beacon`
- `{MUTEX}`
- `{LUA_API}`
- `DLL Sideloading`
""", encoding="utf-8")

    (OUT / "exercise").mkdir(exist_ok=True)
    (OUT / "exercise" / "README.md").write_text("""# Student exercise

## Task 1: Identify malicious updater activity
Search for `GUP.exe`, `WinGUp`, `update.exe`, and malicious update URLs.

## Task 2: Confirm network delivery
Search for `45.76.155.202`, `45.77.31.210`, and `45.32.144.255` in proxy/firewall telemetry.

## Task 3: Identify infection chain variant
Search for `EnumWindowStationsW`, `Cobalt Strike Beacon`, `BluetoothService.exe`, and `log.dll`.

## Task 4: Hunt Chrysalis evidence
Search for `Chrysalis` and `Global\\Jdhfv_1.0.1`.

## Task 5: Write detections
Create detections for unusual GUP.exe writes/downloads, DLL sideloading by Bitdefender-signed binaries outside Program Files, Chrysalis mutex creation, and outbound C2 beaconing.

## Deliverable
Submit a report with affected users/hosts, timeline, indicators, detection logic, and remediation recommendations.
""", encoding="utf-8")

    (OUT / "splunk").mkdir(exist_ok=True)
    (OUT / "splunk" / "starter-searches.spl").write_text(f"""index=* ("GUP.exe" OR "WinGUp" OR "update.exe" OR "45.76.155.202" OR "45.77.31.210" OR "45.32.144.255")
| table _time event.dataset host.name user.name event_type process.name url.full destination.ip file.name severity message

index=* actor_process_signature_vendor="Bitdefender SRL" action_module_path="*log.dll*" actor_process_image_path!="*Program Files*Bitdefender*"
| table _time host.name actor_process_image_name actor_process_image_path action_module_path malware.family severity

index=* (mutex.name="{MUTEX}" OR malware.family="Chrysalis" OR malware.family="Cobalt Strike Beacon")
| table _time event.dataset host.name user.name event_type process.name malware.family mutex.name severity message
""", encoding="utf-8")

    (OUT / "elastic" / "esql").mkdir(parents=True, exist_ok=True)
    (OUT / "elastic" / "esql" / "starter-queries.esql").write_text(f"""FROM logs-*
| WHERE process.name == "GUP.exe" OR file.name == "update.exe" OR destination.ip IN ("45.76.155.202", "45.77.31.210", "45.32.144.255")
| KEEP @timestamp, event.dataset, host.name, user.name, event_type, process.name, url.full, destination.ip, file.name, severity, message
| SORT @timestamp ASC

FROM logs-*
| WHERE actor_process_signature_vendor == "Bitdefender SRL" AND action_module_path LIKE "*log.dll*" AND actor_process_image_path NOT LIKE "*Program Files*Bitdefender*"
| KEEP @timestamp, host.name, actor_process_image_name, actor_process_image_path, action_module_path, malware.family, severity

FROM logs-*
| WHERE mutex.name == "{MUTEX}" OR malware.family IN ("Chrysalis", "Cobalt Strike Beacon")
| KEEP @timestamp, event.dataset, host.name, user.name, event_type, process.name, malware.family, mutex.name, severity, message
""", encoding="utf-8")

    (OUT / "kibana").mkdir(exist_ok=True)
    (OUT / "kibana" / "checklist.md").write_text("""# Kibana / Discover checklist

- Set time range to All time.
- Search for malicious updater indicators.
- Add columns for `process.name`, `url.full`, `destination.ip`, `file.name`, `malware.family`, and `mutex.name`.
- Build a timeline from updater request to download to execution to module load/mutex/C2.
- Save at least one IOC-based and one behavior-based detection query.
""", encoding="utf-8")

    (OUT / "instructor").mkdir(exist_ok=True)
    (OUT / "instructor" / "answer-key.md").write_text(f"""# Instructor answer key

## Core story

A compromised Notepad++ update path selectively delivers malicious update manifests and `update.exe`. Students should identify malicious updater activity, network delivery, Lua/Cobalt Strike and DLL-sideload/Chrysalis variants, mutex evidence, and C2 beaconing.

## Must-find indicators

- `Lotus Blossom`
- `GUP.exe`, `WinGUp`, `update.exe`
- `{', '.join(C2_IPS)}`
- `{', '.join(UPDATE_URLS)}`
- `{SIDELOAD_PROC}`, `{SIDELOAD_DLL}`
- `Chrysalis`, `Cobalt Strike Beacon`
- `{MUTEX}`
- `{LUA_API}`

## Good detections

- `GUP.exe` downloading or writing unusual files to temp paths
- Bitdefender-signed process outside Program Files loading `log.dll`
- Chrysalis mutex creation
- Cobalt Strike or Chrysalis beaconing to listed C2 IPs
- Lua injection markers such as `EnumWindowStationsW`
""", encoding="utf-8")


def main() -> None:
    datasets = {
        "threat-intel.jsonl": threat_intel_events(),
        "updater.jsonl": update_events(),
        "proxy.jsonl": proxy_events(),
        "endpoint.jsonl": endpoint_events(),
        "module-load.jsonl": module_events(),
        "mutex.jsonl": mutex_events(),
        "firewall.jsonl": firewall_events(),
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

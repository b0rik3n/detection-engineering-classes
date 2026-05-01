#!/usr/bin/env python3
from __future__ import annotations

import json
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
START = datetime(2026, 3, 31, 0, 0, tzinfo=timezone.utc)
USERS = ["alice", "bob", "carol", "dlee", "evan", "frank", "grace", "heidi", "svc-build", "svc-backup"]
HOSTS = ["dev-win-01", "dev-linux-02", "dev-mac-03", "fin-win-04", "hr-laptop-05", "eng-ws-06", "sales-lt-07", "ops-win-08"]
SRC_IPS = [f"10.20.{i}.{j}" for i in range(1, 8) for j in range(20, 36)]
DST_IPS = ["142.11.206.73", "198.51.100.44", "203.0.113.25", "104.16.132.229", "140.82.114.4", "13.107.246.45"]
DOMAINS = ["sfrclak.com", "cdn-update-service.com", "login-m365-helpdesk.com", "npm-assets-cache.net", "vpn-session-check.com"]
BENIGN_DOMAINS = ["github.com", "microsoft.com", "ubuntu.com", "cloudflare-dns.com", "docs.python.org", "example.org"]

LABS = {
    "npm-supply-chain": {
        "scenario": "npm supply-chain compromise with suspicious postinstall execution and C2 traffic.",
        "indicator": "npm-assets-cache.net",
        "bad_ip": "198.51.100.44",
        "sources": ["package", "endpoint", "proxy", "dns", "auth"],
        "searches": ["npm-assets-cache.net", "postinstall", "event_type: process_start", "severity: critical"],
    },
    "ot-ics-scada": {
        "scenario": "Unauthorized engineering workstation activity against OT/ICS assets.",
        "indicator": "10.77.4.50",
        "bad_ip": "10.77.4.50",
        "sources": ["modbus", "firewall", "engineering-workstation", "asset", "auth"],
        "searches": ["write_multiple_registers", "10.77.4.50", "event_type: plc_write", "severity: critical"],
    },
    "cloud-iam-abuse": {
        "scenario": "Compromised cloud identity performs privilege discovery and role escalation.",
        "indicator": "AssumeRole",
        "bad_ip": "203.0.113.25",
        "sources": ["cloudtrail", "signin", "iam", "vpc-flow", "edr"],
        "searches": ["AssumeRole", "AttachUserPolicy", "203.0.113.25", "severity: high"],
    },
    "ransomware-initial-access-lateral-movement": {
        "scenario": "Initial access followed by credential access, lateral movement, and ransomware staging.",
        "indicator": "rclone.exe",
        "bad_ip": "198.51.100.44",
        "sources": ["endpoint", "auth", "smb", "dns", "firewall"],
        "searches": ["rclone.exe", "failed_login", "admin$", "severity: critical"],
    },
    "exchange-email-server-exploitation": {
        "scenario": "Internet-facing Exchange exploitation leading to web shell and suspicious PowerShell.",
        "indicator": "owa-auth.aspx",
        "bad_ip": "198.51.100.44",
        "sources": ["iis", "exchange", "endpoint", "powershell", "firewall"],
        "searches": ["owa-auth.aspx", "New-MailboxExportRequest", "powershell", "severity: critical"],
    },
    "browser-extension-supply-chain-risk": {
        "scenario": "Malicious browser extension update creates suspicious outbound behavior.",
        "indicator": "cdn-update-service.com",
        "bad_ip": "142.11.206.73",
        "sources": ["browser", "endpoint", "proxy", "dns", "identity"],
        "searches": ["cdn-update-service.com", "extension_update", "chrome.exe", "severity: high"],
    },
    "m365-oauth-app-abuse": {
        "scenario": "Malicious OAuth application consent and mailbox access in Microsoft 365.",
        "indicator": "Mail.ReadWrite",
        "bad_ip": "203.0.113.25",
        "sources": ["audit", "signin", "oauth", "graph", "mailbox"],
        "searches": ["Mail.ReadWrite", "Consent to application", "203.0.113.25", "severity: high"],
    },
    "kubernetes-runtime-threats": {
        "scenario": "Kubernetes runtime compromise with suspicious pod exec and crypto-mining behavior.",
        "indicator": "xmrig",
        "bad_ip": "198.51.100.44",
        "sources": ["kube-audit", "container", "network", "node", "cloud"],
        "searches": ["xmrig", "pods/exec", "privileged", "severity: critical"],
    },
    "vpn-edge-device-exploitation": {
        "scenario": "VPN edge exploitation followed by anomalous sessions and internal scanning.",
        "indicator": "vpn-session-check.com",
        "bad_ip": "203.0.113.25",
        "sources": ["vpn", "firewall", "auth", "dns", "edr"],
        "searches": ["vpn-session-check.com", "impossible_travel", "port_scan", "severity: high"],
    },
    "ot-ics-protocol-misuse-advanced": {
        "scenario": "Advanced OT protocol misuse with staged discovery and unsafe write activity.",
        "indicator": "write_multiple_registers",
        "bad_ip": "10.77.4.50",
        "sources": ["modbus", "dnp3", "opcua", "firewall", "asset"],
        "searches": ["write_multiple_registers", "operate", "firmware_update", "severity: critical"],
    },
}


def timestamp(n: int, source_idx: int) -> str:
    dt = START + timedelta(minutes=n, seconds=(source_idx * 7 + n * 13) % 60)
    return dt.isoformat().replace("+00:00", "Z")


def common_event(lab: str, source: str, i: int, cfg: dict, source_idx: int) -> dict:
    suspicious = i in {12, 13, 14, 27, 28, 46, 47, 63, 64, 81, 82, 94}
    user = USERS[(i + source_idx) % len(USERS)]
    host = HOSTS[(i + source_idx) % len(HOSTS)]
    domain = cfg["indicator"] if "." in cfg["indicator"] and suspicious else random.choice(BENIGN_DOMAINS)
    dst = cfg["bad_ip"] if suspicious else random.choice(DST_IPS[1:])
    action = action_for(source, suspicious, cfg)
    event = {
        "@timestamp": timestamp(i, source_idx),
        "event.dataset": source,
        "event.category": category_for(source),
        "event.action": action,
        "event_type": action,
        "host.name": host,
        "user.name": user,
        "source.ip": SRC_IPS[(i + source_idx) % len(SRC_IPS)],
        "destination.ip": dst,
        "domain": domain if "." in domain else "",
        "severity": severity_for(source, suspicious),
        "message": message_for(lab, source, suspicious, cfg),
        "lab.name": lab,
        "scenario.name": cfg["scenario"],
    }
    event.update(extra_fields(source, i, suspicious, cfg))
    return event


def category_for(source: str) -> str:
    if source in {"dns", "proxy", "firewall", "vpc-flow", "network", "vpn", "modbus", "dnp3", "opcua"}:
        return "network"
    if source in {"auth", "signin", "identity", "iam", "oauth"}:
        return "authentication"
    if source in {"endpoint", "edr", "powershell", "container", "node", "engineering-workstation"}:
        return "process"
    if source in {"cloudtrail", "audit", "exchange", "graph", "mailbox", "kube-audit"}:
        return "configuration"
    return "package" if source == "package" else "host"


def action_for(source: str, suspicious: bool, cfg: dict) -> str:
    table = {
        "dns": "dns_query", "proxy": "http_request", "firewall": "port_scan" if suspicious and cfg.get("indicator") == "vpn-session-check.com" else ("allowed" if suspicious else "allowed"),
        "package": "postinstall" if suspicious else "install", "endpoint": "process_start",
        "edr": "process_start",
        "signin": "risky_signin" if suspicious else "signin_success",
        "auth": "impossible_travel" if suspicious and cfg.get("indicator") == "vpn-session-check.com" else ("failed_login" if suspicious else "login_success"), "iam": "AttachUserPolicy" if suspicious else "ListRoles",
        "cloudtrail": "AssumeRole" if suspicious else "DescribeInstances", "vpc-flow": "ACCEPT",
        "modbus": "write_multiple_registers" if suspicious else "read_holding_registers", "dnp3": "operate" if suspicious else "read",
        "opcua": "write" if suspicious else "read", "engineering-workstation": "plc_write" if suspicious else "project_open",
        "asset": "firmware_update" if suspicious else "asset_inventory", "smb": "admin_share_access" if suspicious else "file_read",
        "iis": "webshell_upload" if suspicious else "http_request", "exchange": "New-MailboxExportRequest" if suspicious else "Get-Mailbox",
        "powershell": "encoded_command" if suspicious else "script_block", "browser": "extension_update" if suspicious else "page_load",
        "identity": "token_refresh", "audit": "Consent to application" if suspicious else "UserLoggedIn",
        "oauth": "GrantConsent" if suspicious else "ListApps", "graph": "Mail.ReadWrite" if suspicious else "User.Read",
        "mailbox": "mass_mail_read" if suspicious else "message_read", "kube-audit": "pods/exec" if suspicious else "get pods",
        "container": "exec" if suspicious else "start", "network": "egress_connection", "node": "privileged_process" if suspicious else "systemd_start",
        "cloud": "CreateClusterRoleBinding" if suspicious else "DescribeCluster", "vpn": "new_session" if suspicious else "login_success",
    }
    return table.get(source, "event")


def severity_for(source: str, suspicious: bool) -> str:
    if not suspicious:
        return random.choice(["info", "info", "low"])
    if source in {"endpoint", "edr", "powershell", "container", "modbus", "dnp3", "opcua", "asset", "kube-audit"}:
        return "critical"
    return "high"


def message_for(lab: str, source: str, suspicious: bool, cfg: dict) -> str:
    if suspicious:
        return f"Suspicious {source} activity related to {cfg['indicator']}"
    return f"Routine {source} telemetry for {lab}"


def extra_fields(source: str, i: int, suspicious: bool, cfg: dict) -> dict:
    indicator = cfg["indicator"]
    bad_ip = cfg["bad_ip"]
    if source == "package":
        return {"package.name": "event-stream-helper" if suspicious else random.choice(["axios", "lodash", "react", "vite"]), "package.version": f"1.{i % 9}.{i % 17}", "script.name": "postinstall" if suspicious else "install"}
    if source in {"endpoint", "edr", "engineering-workstation", "powershell", "container", "node"}:
        proc = "powershell.exe" if "PowerShell" in cfg["scenario"] or source == "powershell" else ("xmrig" if indicator == "xmrig" and suspicious else "curl.exe" if suspicious else random.choice(["chrome.exe", "python.exe", "bash", "svchost.exe"]))
        return {"process.name": proc, "process.command_line": f"{proc} connect {indicator} {bad_ip}" if suspicious else f"{proc} normal activity"}
    if source in {"dns", "proxy", "browser"}:
        domain = indicator if "." in indicator and suspicious else random.choice(BENIGN_DOMAINS)
        return {"url.full": f"https://{domain}/resource/{i}", "dns.question.name": domain}
    if source in {"firewall", "vpc-flow", "network", "vpn"}:
        return {"destination.port": random.choice([443, 8443, 8000, 3389]) if suspicious else random.choice([80, 443, 53]), "network.transport": "tcp", "network.bytes": 90000 + i if suspicious else 1200 + i}
    if source in {"cloudtrail", "iam", "audit", "oauth", "graph", "cloud"}:
        return {"cloud.provider": "aws" if source in {"cloudtrail", "iam"} else "azure", "cloud.account.id": f"acct-{1000 + i}", "user_agent.original": "aws-cli/2.13" if suspicious else "console"}
    if source in {"signin", "auth", "identity"}:
        return {"source.geo.country_iso_code": "RU" if suspicious else "US", "mfa.result": "not_challenged" if suspicious else "satisfied"}
    if source in {"modbus", "dnp3", "opcua"}:
        return {"ot.asset.id": f"PLC-{i % 6}", "ot.command": action_for(source, suspicious, cfg), "destination.port": 502 if source == "modbus" else 20000}
    if source == "asset":
        return {"asset.id": f"PLC-{i % 6}", "asset.role": random.choice(["plc", "hmi", "engineering_workstation"])}
    if source == "smb":
        return {"file.path": "\\\\host\\admin$\\stage.exe" if suspicious else "\\\\fileserver\\share\\doc.txt"}
    if source in {"iis", "exchange", "mailbox"}:
        return {"url.path": "/aspnet_client/owa-auth.aspx" if suspicious else "/owa/", "http.response.status_code": 200}
    if source == "kube-audit":
        return {"kubernetes.verb": "create" if suspicious else "get", "kubernetes.resource": "pods/exec" if suspicious else "pods", "kubernetes.namespace": "prod"}
    return {}


def write_jsonl(path: Path, events: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for event in events:
            f.write(json.dumps(event, separators=(",", ":")) + "\n")


def main() -> None:
    random.seed(1337)
    for lab, cfg in LABS.items():
        lab_dir = ROOT / "labs" / lab / "data"
        combined = []
        for source_idx, source in enumerate(cfg["sources"]):
            events = [common_event(lab, source, i, cfg, source_idx) for i in range(100)]
            write_jsonl(lab_dir / f"{source}.jsonl", events)
            combined.extend(events)
        combined.sort(key=lambda e: e["@timestamp"])
        write_jsonl(lab_dir / "combined.jsonl", combined)
        readme = [
            f"# {lab} data pack",
            "",
            f"Scenario: {cfg['scenario']}",
            "",
            "Files:",
            "",
        ]
        for source in cfg["sources"]:
            readme.append(f"- `{source}.jsonl` - 100 synthetic {source} events")
        readme.extend([
            f"- `combined.jsonl` - {len(combined)} events merged and sorted by timestamp",
            "",
            "Suggested searches:",
            "",
        ])
        for search in cfg["searches"]:
            readme.append(f"- `{search}`")
        readme.append("")
        (lab_dir / "README.md").write_text("\n".join(readme), encoding="utf-8")
        print(f"{lab}: {len(cfg['sources'])} sources, {len(combined)} combined events")


if __name__ == "__main__":
    main()

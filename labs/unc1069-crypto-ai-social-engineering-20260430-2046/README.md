# de-lab-unc1069-crypto-ai-social-engineering-20260430-2046

Detection engineering lab based on the Google Cloud/Mandiant article: **UNC1069 Targets Cryptocurrency Sector with New Tooling and AI-Enabled Social Engineering**.

Timestamped class name: `unc1069-crypto-ai-social-engineering-20260430-2046`

## Scenario

UNC1069 targets a cryptocurrency/DeFi organization through a compromised Telegram account, fake Zoom meeting, AI-enabled social engineering, and a ClickFix-style troubleshooting ruse. The victim executes macOS or Windows commands that fetch payloads from attacker infrastructure, followed by deployment of multiple malware families used to capture host data, browser data, credentials, and session tokens.

## Known indicators and behaviors

- Threat actor: `UNC1069`
- Fake Zoom domain: `zoom.uswe05.us`
- Payload domain: `mylingocoin.com`
- Payload URL: `http://mylingocoin.com/audio/fix/6454694440`
- Payload ID: `6454694440`
- Malware/tooling: `WAVESHAPER, SUGARLOADER, HYPERCALL, HIDDENCALL, SILENCELIFT, DEEPBREATH, CHROMEPUSH`
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

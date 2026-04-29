# Instructor Answer Key

## Expected core findings
1. Compromised package versions observed in package telemetry:
   - axios@1.14.1
   - axios@0.30.4
   - plain-crypto-js@4.2.1
2. Suspicious process chain after install:
   - npm/postinstall activity followed by script interpreters (PowerShell, wscript/cscript, python, osascript/shell)
3. Network indicators:
   - Domain `sfrclak.com`
   - IP `142.11.206.73`
   - Endpoint `/6202033`
4. Persistence artifacts by OS:
   - macOS: `/Library/Caches/com.apple.act.mond`
   - Windows: `%PROGRAMDATA%\\wt.exe`, `%TEMP%\\6202033.vbs`, `%TEMP%\\6202033.ps1`
   - Linux: `/tmp/ld.py`

## Expected timeline (example)
- T0: package install (compromised version)
- T0 + 1-5m: postinstall/setup script execution
- T0 + 2-10m: script interpreter + payload execution
- T0 + 3-15m: outbound C2 DNS/proxy/network activity
- T0 + 5-20m: persistence artifact creation

## Minimum passing standard
- Correct IOC query in both SPL and ES|QL
- At least one behavioral detection in both platforms
- Correlation logic with explicit time window
- Basic ATT&CK mapping and triage summary

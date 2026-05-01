# npm-supply-chain data pack

Scenario: npm supply-chain compromise leading to postinstall execution, persistence artifacts, and C2 traffic.

Known IOCs for this lab:

- Domain: `sfrclak.com`
- IP: `142.11.206.73`
- URL: `http://sfrclak.com:8000/6202033`
- Packages: `axios@1.14.1`, `axios@0.30.4`, `plain-crypto-js@4.2.1`
- macOS artifact: `/Library/Caches/com.apple.act.mond`
- Windows artifacts: `%PROGRAMDATA%\wt.exe`, `%TEMP%\6202033.vbs`, `%TEMP%\6202033.ps1`
- Linux artifact: `/tmp/ld.py`

Files:

- `package.jsonl` - 100 package install/postinstall events
- `endpoint.jsonl` - 100 endpoint/process/file artifact events
- `proxy.jsonl` - 100 HTTP/proxy events
- `dns.jsonl` - 100 DNS events
- `auth.jsonl` - 100 authentication context events
- `combined.jsonl` - 500 events merged and sorted by timestamp

Suggested searches:

- `sfrclak.com`
- `142.11.206.73`
- `http://sfrclak.com:8000/6202033`
- `axios@1.14.1`
- `axios@0.30.4`
- `plain-crypto-js@4.2.1`
- `/Library/Caches/com.apple.act.mond`
- `%PROGRAMDATA%\wt.exe`
- `%TEMP%\6202033.vbs`
- `%TEMP%\6202033.ps1`
- `/tmp/ld.py`

# Student Guide: Cross-Platform Detection Engineering Lab

## Core objective
Build equivalent detections in Splunk and Elastic, then compare precision, performance, and maintainability.

## Modules
1. Data familiarization
2. IOC detections
3. Behavioral detections
4. Correlation detection
5. Kibana work
6. Comparison write-up

## Deliverables
- SPL queries (IOC, behavior, correlation)
- ES|QL queries (IOC, behavior, correlation)
- Kibana evidence (Discover screenshots/notes, rule config summary)
- 1-page comparison write-up (SPL vs ES|QL)
- ATT&CK mapping table

## Scenario IOCs (for lab)
- Domain: `sfrclak.com`
- IP: `142.11.206.73`
- URL: `http://sfrclak.com:8000/6202033`
- Packages: `axios@1.14.1`, `axios@0.30.4`, `plain-crypto-js@4.2.1`
- OS indicators:
  - macOS: `/Library/Caches/com.apple.act.mond`
  - Windows: `%PROGRAMDATA%\\wt.exe`, `%TEMP%\\6202033.vbs`, `%TEMP%\\6202033.ps1`
  - Linux: `/tmp/ld.py`

## Success criteria
- Detect package-level compromise indicators
- Detect suspicious postinstall execution chains
- Correlate package + process + outbound network events within a time window
- Explain platform tradeoffs using evidence

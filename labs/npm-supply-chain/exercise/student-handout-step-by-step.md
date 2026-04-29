# Student Handout: Detection Engineering Practical (Splunk + Elastic)

## Lab title
Cross-Platform Detection Engineering, npm Supply-Chain Compromise

## What you are doing
You will investigate a simulated software supply-chain incident and build equivalent detections in two ecosystems:
- **Splunk (SPL)**
- **Elastic (Kibana + ES|QL)**

You are not only trying to “find bad.” You are practicing how to:
1. Build detection logic from incident evidence.
2. Tune to reduce noise.
3. Correlate multi-source telemetry.
4. Explain tradeoffs between detection platforms.

---

## Scenario summary
Compromised npm package versions were installed on developer endpoints. Those installs triggered suspicious script execution, outbound command-and-control (C2) traffic, and persistence artifacts across Windows, Linux, and macOS.

### Known IOCs for this lab
- Domain: `sfrclak.com`
- IP: `142.11.206.73`
- URL: `http://sfrclak.com:8000/6202033`
- Packages:
  - `axios@1.14.1`
  - `axios@0.30.4`
  - `plain-crypto-js@4.2.1`
- Host artifacts:
  - macOS: `/Library/Caches/com.apple.act.mond`
  - Windows: `%PROGRAMDATA%\wt.exe`, `%TEMP%\6202033.vbs`, `%TEMP%\6202033.ps1`
  - Linux: `/tmp/ld.py`

---

## Learning outcomes
By the end of lab, you should be able to:
- Translate threat intelligence into query logic.
- Hunt IOCs and behavior in both SPL and ES|QL.
- Build correlation detections with a defensible time window.
- Produce investigation evidence in Kibana Discover.
- Explain why two equivalent detections can differ in fidelity.

---

## Required deliverables (submit all)
1. IOC detections in SPL and ES|QL.
2. Behavioral detections in SPL and ES|QL.
3. Correlation detections in SPL and ES|QL.
4. Kibana evidence (Discover notes/screenshots + rule setup summary).
5. One-page SPL vs ES|QL comparison (precision, performance, maintainability).
6. ATT&CK mapping table.

---

## Real threat intel references (for enrichment)
Use these references for ATT&CK mapping, reasoning, and triage context.

- Unit 42, axios supply chain attack:
  - https://unit42.paloaltonetworks.com/axios-supply-chain-attack/
- The DFIR Report, Bumblebee to Akira:
  - https://thedfirreport.com/2025/11/04/from-bing-search-to-ransomware-bumblebee-and-adaptixc2-deliver-akira-2/
- Microsoft Threat Intelligence, WhatsApp malware campaign:
  - https://www.microsoft.com/en-us/security/blog/2026/03/31/whatsapp-malware-campaign-delivers-vbs-payloads-msi-backdoors/
- Cisco Talos, LucidRook malware:
  - https://blog.talosintelligence.com/new-lua-based-malware-lucidrook/
- Google Threat Intelligence, BRICKSTORM campaign:
  - https://cloud.google.com/blog/topics/threat-intelligence/brickstorm-espionage-campaign
- Volexity, Exchange exploitation case study:
  - https://www.volexity.com/blog/2021/03/02/active-exploitation-of-microsoft-exchange-zero-day-vulnerabilities/

Note: these references provide authentic reporting patterns and IOC structure. Your synthetic lab data will not match every detail.

---

## Before you begin (5 minutes)
1. Confirm your Splunk time range covers event timestamps.
2. Confirm Kibana index pattern points to your demo data.
3. Open these files side-by-side:
   - `splunk/starter-queries.spl`
   - `elastic/esql/starter-queries.esql`
   - `kibana/checklist.md`
4. Create a lab notes document.

In your notes, create section headers now:
- Field mapping
- IOC results
- Behavioral results
- Correlation results
- Kibana evidence
- ATT&CK mapping
- SPL vs ES|QL comparison

---

## Step-by-step workflow

## Step 1: Data familiarization and field mapping

### Goal
Understand where equivalent data lives in each platform.

### Splunk actions
1. Run:
   - `index=detection_demo | head 50`
2. Identify fields needed for your detections:
   - host/user/process/file/network/package

### Elastic/Kibana actions
1. Open Discover.
2. Filter to lab index pattern (e.g., `detection_demo_*`).
3. Inspect ECS fields and sample values.

### Build your field crosswalk
At minimum map:
- `host` ↔ `host.name`
- `user` ↔ `user.name`
- `process_name` ↔ `process.name`
- `process_commandline` ↔ `process.command_line`
- `file_path` ↔ `file.path`
- `domain` ↔ `domain`
- `destination_ip`/`ip` ↔ `destination.ip`
- `package_name` ↔ `package.name`
- `package_version` ↔ `package.version`

### What to record
- 8+ mapped fields
- Any null/optional fields you noticed
- Any field normalization differences

---

## Step 2: IOC detections

### Goal
Find exact known-bad indicators quickly and accurately.

### Splunk actions
1. Run IOC starter query from `splunk/starter-queries.spl`.
2. Verify matches for:
   - domain, IP, URL, package@version
3. Add summary stats:
   - impacted hosts
   - impacted users
   - first seen / last seen

### ES|QL actions
1. Run IOC query from `elastic/esql/starter-queries.esql`.
2. Verify equivalent matches.
3. Ensure output includes timestamp, host, IOC type.

### What to record
- Distinct hosts with IOC hits
- Distinct users with IOC hits
- First and last timestamps
- Which IOC types hit most often

### Validation question
Do SPL and ES|QL return the same logical incidents? If not, explain exactly why (field mismatch, data type, parser behavior, null handling, etc.).

---

## Step 3: Behavioral detections

### Goal
Move beyond “known bad” and detect suspicious execution patterns.

### Detection pattern to model
- Package install/postinstall context
- Script or interpreter execution:
  - `powershell`, `wscript/cscript`, `python`, `osascript`, `zsh/bash/sh`
- Suspicious command-line fragments:
  - `ExecutionPolicy Bypass`, `setup.js`, known dropper paths

### Splunk actions
1. Run behavioral starter query.
2. Tune to improve precision, for example:
   - parent process constraints (`npm`, package managers)
   - commandline contains both install context + execution flags
   - host scope (developer endpoints only)
3. Capture before/after counts.

### ES|QL actions
1. Run behavioral starter query.
2. Apply equivalent filters in ES|QL.
3. Re-check output quality and document differences.

### What to record
- Final behavioral query in both languages
- Tuning changes you made and why
- Before/after result volume
- Observed false positives and how you reduced them

---

## Step 4: Persistence artifact detections

### Goal
Detect host-level artifacts consistent with post-exploitation persistence.

### Splunk actions
1. Run artifact query from starter pack.
2. Confirm host artifacts by OS/path.

### ES|QL actions
1. Run equivalent artifact query.
2. Confirm same host/path timeline.

### What to record
- Host
- User
- Process
- File path
- Event timestamp

### Analyst note
This step is high value for triage. IOC-only alerts can be noisy. Disk artifacts strengthen confidence.

---

## Step 5: Correlation detection (high confidence)

### Goal
Build logic that requires **all three** signals in a single window:
1. Compromised package event
2. Suspicious process event
3. Outbound C2 event

### Recommended window
Start with 30 minutes. Then test 15 and 60 minutes to observe sensitivity.

### Splunk actions
1. Run correlation starter SPL.
2. Verify all three flags are present for the same host/window.
3. Tune if needed.

### ES|QL actions
1. Run correlation starter ES|QL.
2. Validate equivalent host/window hits.
3. Compare result counts with SPL.

### What to record
- Final correlated host list
- Time window used
- Why this is high confidence
- What changed when window size changed

### Validation question
What fails when the window is too tight? What noise appears when it is too wide?

---

## Step 6: Kibana practical execution

Use `kibana/checklist.md`. Every box should be completed.

### Required work
1. **Discover pivot notes**
   - Start at package event.
   - Pivot to process execution on same host.
   - Pivot to network C2 activity in nearby time.
2. **ES|QL hunt evidence**
   - Save or export IOC, behavior, and correlation outputs.
3. **Elastic Security rule setup**
   - IOC rule (low/medium)
   - Behavioral rule (medium/high)
   - Correlation rule (high)
4. **Visual evidence**
   - Timeline by host
   - Top suspicious processes
   - Destination domain/IP chart
   - Artifact-by-OS chart

### What to record
- Rule names
- Rule severity/priority
- Rule scheduling interval
- Triage notes or investigation guide text

---

## Step 7: ATT&CK mapping

### Goal
Map each meaningful detection to ATT&CK tactics/techniques.

Use this template:

| Detection | Data source | ATT&CK tactic | ATT&CK technique | Why this mapping fits |
|---|---|---|---|---|
| IOC domain/IP hit | DNS/Proxy | Command and Control | T1071 (example) | Outbound comms to known C2 |

### What to record
- At least 4 mappings
- One sentence rationale per mapping

Tip: Avoid vague mappings. Tie each mapping to observed telemetry.

---

## Step 8: SPL vs ES|QL comparison write-up (1 page)

Answer these directly:
1. Which platform was faster for iterative hunting and why?
2. Which platform made correlation easier for this scenario and why?
3. Which query language appears easier to maintain for your team?
4. What precision differences did you observe?
5. What performance differences did you observe?
6. What is your production recommendation for this use case?

### Write-up quality bar
- Use evidence (result counts, fields, screenshots, query behavior).
- Avoid generic statements like “it depends.”
- Be specific about tradeoffs.

---

## Step 9: Final submission checklist

Before you submit, verify:
- [ ] IOC queries complete in SPL and ES|QL
- [ ] Behavioral queries complete in SPL and ES|QL
- [ ] Correlation queries complete in SPL and ES|QL
- [ ] Kibana checklist complete
- [ ] ATT&CK mapping table included
- [ ] 1-page comparison included
- [ ] Evidence attached (screenshots/exports)
- [ ] Queries are readable and commented

---

## Recommended time plan (~2h 40m)
- Setup + field mapping: 20 min
- IOC detections: 20 min
- Behavioral detections: 30 min
- Artifact detections: 15 min
- Correlation detections: 25 min
- Kibana practical: 25 min
- ATT&CK + write-up: 20 min
- Final QA + submission: 5 min

---

## Troubleshooting guide

### Problem: No IOC hits
- Confirm time range first.
- Confirm index/index pattern.
- Confirm field names are correct for your environment.

### Problem: Too many behavior hits
- Add parent process constraints.
- Add commandline context requirements.
- Scope to relevant host class.

### Problem: Correlation query returns zero
- Validate each signal independently first.
- Increase window temporarily.
- Check null handling and field availability.

### Problem: SPL and ES|QL disagree
- Compare schema mapping line-by-line.
- Check case sensitivity and string matching operators.
- Check how each platform handles missing fields.

---

## Submission format (recommended)
- `queries/spl/*.spl`
- `queries/esql/*.esql`
- `evidence/*.png` or exported CSV/JSON
- `report/comparison.md`
- `report/attack-mapping.md`

---

## Final reminder
Think like an analyst, not just a query writer.
A strong submission shows:
- correct logic,
- deliberate tuning,
- reproducible evidence,
- and clear reasoning.

Good luck. Treat this as a real SOC case.
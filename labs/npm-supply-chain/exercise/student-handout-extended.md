# Extended Student Handout
## Detection Engineering Practical, npm Supply-Chain Compromise

## Beginner-friendly note
This version is written for students who may be new to detection engineering, Splunk, Elastic, or SOC workflows.
If a term feels unfamiliar, check the **Quick Glossary** section before continuing.

---

## 1) Why this lab exists
This lab is designed to train you to think like a detection engineer, not just a query author.

A detection engineer’s job is to:
- turn threat information into measurable telemetry logic,
- test that logic across different platforms,
- tune detections to reduce false positives,
- and communicate detection quality clearly.

In this exercise, you will do that work in both **Splunk (SPL)** and **Elastic (Kibana + ES|QL)** using the same scenario and dataset.

---

## 2) Lab objective
You will build equivalent detections in two platforms and compare tradeoffs:
- precision,
- performance,
- and maintainability.

You are expected to show your reasoning at each step.

---

## 3) Scenario context
A supply-chain compromise impacted npm package installs on developer endpoints.
After install, suspicious script execution occurred, followed by outbound C2 traffic and host artifacts consistent with persistence.

### Training aide, read these first (recommended)
These two articles provide excellent context for why this lab matters and how analysts describe this attack pattern in real reporting:

1. Unit 42, axios supply-chain attack
   - https://unit42.paloaltonetworks.com/axios-supply-chain-attack/
2. Koi Security research write-up (axios compromise)
   - https://www.koi.ai/blog/axios-compromised-a-supply-chain-attack-on-npms-most-popular-http-client

Tip: read these before writing your ATT&CK mappings and final comparison section.

### IOC set for this lab
- Domain: `sfrclak.com`
- IP: `142.11.206.73`
- URL: `http://sfrclak.com:8000/6202033`
- Compromised packages:
  - `axios@1.14.1`
  - `axios@0.30.4`
  - `plain-crypto-js@4.2.1`
- Host artifacts:
  - macOS: `/Library/Caches/com.apple.act.mond`
  - Windows: `%PROGRAMDATA%\wt.exe`, `%TEMP%\6202033.vbs`, `%TEMP%\6202033.ps1`
  - Linux: `/tmp/ld.py`

---

## 4) Expected deliverables
You must submit:
1. IOC detections in SPL and ES|QL.
2. Behavioral detections in SPL and ES|QL.
3. Correlation detections in SPL and ES|QL.
4. Kibana investigation evidence.
5. A one-page platform comparison.
6. ATT&CK mapping table.

Optional bonus:
- a short “production hardening” section describing alert tuning and deployment approach.

---

## 5) Quick Glossary (read this first)
- **Detection engineering**: writing logic that finds suspicious or malicious activity in logs.
- **IOC (Indicator of Compromise)**: a known bad value such as a domain, IP, hash, or malicious package version.
- **Behavioral detection**: detection logic based on what something does, not just known bad values.
- **Correlation**: combining multiple weak signals into one stronger alert.
- **Telemetry**: logs/events collected from systems (endpoint, DNS, proxy, package manager, etc.).
- **SPL**: Splunk Processing Language, used to query data in Splunk.
- **ES|QL**: Elasticsearch Query Language, used to hunt and analyze data in Elastic.
- **Kibana Discover**: Elastic interface for searching and pivoting through raw events.
- **ECS**: Elastic Common Schema, standardized field naming in Elastic.
- **ATT&CK**: MITRE ATT&CK framework used to map adversary behavior to known tactics/techniques.
- **False positive**: alert that looks suspicious but is actually benign.
- **Tuning**: adjusting logic to reduce false positives while keeping true detections.

---

## 6) Click-by-click startup (beginner mode)

### Splunk startup
1. Open Splunk in your browser.
2. Click **Search & Reporting** app.
3. At top-right, set time range to **All time** (or a range covering the lab timestamps).
4. In the search bar, paste:
   - `index=detection_demo | head 20`
5. Press **Enter**.

If data appears, Splunk is ready.

### Kibana startup
1. Open Kibana in your browser.
2. Click menu icon (top-left) → **Analytics** → **Discover**.
3. Select index pattern (for example `detection_demo_*`).
4. Set time picker (top-right) to include all lab data.
5. In KQL bar, use `*` and press **Refresh**.

If rows appear, Kibana is ready.

### If you see zero rows
- Re-check time range first.
- Confirm index name with instructor.
- Click Refresh.

---

## 7) Materials you must open first
- `splunk/starter-queries.spl`
- `elastic/esql/starter-queries.esql`
- `kibana/checklist.md`
- `data/events.jsonl` (reference)

Create a notebook or markdown notes file with these sections:
- Environment
- Field mapping
- IOC detection
- Behavioral detection
- Correlation detection
- Kibana evidence
- ATT&CK mapping
- SPL vs ES|QL comparison
- Final conclusions

---

## 8) Step-by-step workflow (very detailed)

## Step 0, Environment validation
### Goal
Confirm your lab environment is correct before doing analysis.

### Actions
1. Confirm your Splunk index is available and populated (expected index: `detection_demo`).
2. Confirm your Elastic index pattern resolves events (e.g., `detection_demo_*`).
3. Set time range in both tools to include the event timestamps in the dataset.
4. Test with a broad query in each platform.

### Expected output
- Splunk: table rows with fields like host, user, event type.
- Kibana Discover: rows with `@timestamp` and ECS fields.

### Why this matters
Most failed detections are not bad logic. They are wrong time range, wrong index, or field mismatch.

### Record
- Splunk instance name
- Kibana space/index pattern
- Time range used

---

## Step 1, Data familiarization and schema mapping
### Goal
Understand how equivalent facts are represented in each platform.

### Splunk actions
1. Run:
   - `index=detection_demo | head 50`
2. Identify fields by category:
   - identity: host/user
   - process: name/parent/commandline
   - network: domain/ip/url
   - file: path/action
   - package: name/version/action

### Elastic actions
1. Open Kibana Discover.
2. Filter to the lab dataset.
3. Inspect ECS field structure for the same categories.

### Build a crosswalk table
At minimum map:
- `host` ↔ `host.name`
- `user` ↔ `user.name`
- `process_name` ↔ `process.name`
- `parent_process_name` ↔ `process.parent.name`
- `process_commandline` ↔ `process.command_line`
- `file_path` ↔ `file.path`
- `domain` ↔ `domain`
- `destination_ip`/`ip` ↔ `destination.ip`
- `url` ↔ `url.full`
- `package_name` ↔ `package.name`
- `package_version` ↔ `package.version`

### Expected output
A completed field mapping table with 8+ fields.

### Why this matters
Detection parity fails when schema assumptions differ. Cross-platform mapping is foundational.

### Record
- final mapping table (8+ fields)
- unknown or nullable fields
- field normalization notes

---

## Step 2, IOC detections
### Goal
Detect known indicators quickly and accurately in both stacks.

### Splunk actions
1. Open `splunk/starter-queries.spl`.
2. Copy IOC query block.
3. Paste into Splunk search bar and run.
4. Sort by time ascending if needed.

### ES|QL actions
1. In Kibana, open ES|QL query editor.
2. Open `elastic/esql/starter-queries.esql`.
3. Copy IOC query block and run.

### Expected output
You should see IOC matches for at least:
- `sfrclak.com`
- `142.11.206.73`
- one or more compromised package versions

### If expected output is missing
- verify exact field names,
- verify time range,
- verify your index pattern includes network + package events.

### Record
- distinct hosts/users impacted
- first and last IOC event timestamps
- IOC category hit counts

---

## Step 3, Behavioral detection logic
### Goal
Detect suspicious execution behavior independent of static IOC match.

### Behavioral pattern
Build detections for:
1. package install or postinstall context,
2. interpreter execution (`powershell`, `wscript/cscript`, `python`, `osascript`, `zsh/bash/sh`),
3. suspicious commandline fragments (`ExecutionPolicy Bypass`, `setup.js`, known dropper path patterns).

### Splunk actions
1. Copy behavioral query from starter file and run.
2. Tune in stages:
   - Stage A: broad behavior logic
   - Stage B: add parent-process constraints
   - Stage C: add commandline constraints
   - Stage D: remove obvious benign patterns

### ES|QL actions
1. Run behavioral ES|QL starter query.
2. Mirror SPL tuning intent.

### Expected output
A smaller, cleaner result set showing likely malicious chains.

### Record
- final SPL and ES|QL behavior queries
- each tuning step and rationale
- before/after event counts

---

## Step 4, Persistence artifact detections
### Goal
Find host artifacts that support a higher-confidence compromise story.

### Splunk actions
1. Run file artifact query from starter pack.
2. Validate path matches by platform.

### ES|QL actions
1. Run corresponding ES|QL artifact query.
2. Validate matching host and timeline.

### Expected output
Hits for one or more known artifact paths.

### Record
For each hit:
- timestamp
- host
- user
- process
- artifact path

---

## Step 5, Correlation detection
### Goal
Create a high-confidence detection requiring three signals in one time window:
1. compromised package event,
2. suspicious process event,
3. outbound C2 signal.

### Default window
Start with 30 minutes. Then test 15 and 60 to observe detection sensitivity.

### Splunk actions
1. Run starter correlation SPL.
2. Verify all three conditions are present per host/time bucket.

### ES|QL actions
1. Run starter correlation ES|QL.
2. Confirm equivalent host/window results.

### Expected output
A short list of high-confidence hosts, not a huge list.

### Record
- correlated host list
- selected time window and reason
- result differences by window size

---

## Step 6, Kibana practical execution
### Goal
Demonstrate analyst workflow and operationalization in Elastic.

### Required tasks
1. In Discover, pivot through:
   - package event → process event → network event.
2. Run ES|QL IOC, behavioral, and correlation hunts.
3. Create three Elastic Security rules:
   - IOC rule
   - behavioral rule
   - correlation rule
4. Capture required visual evidence:
   - timeline by host
   - suspicious process chart
   - destination domain/IP chart
   - artifact distribution by OS

### Beginner click path for rules
1. Kibana menu → **Security** → **Rules**.
2. Click **Create new rule**.
3. Choose query-based rule type.
4. Paste query.
5. Set severity.
6. Set schedule.
7. Add investigation notes.
8. Save.

### Record
- rule names
- severities
- schedules
- investigation notes/guidance
- screenshots or exported result sets

---

## Step 7, ATT&CK mapping
### Goal
Map your detections to ATT&CK with clear justifications.

Use this template:

| Detection | Data source | ATT&CK tactic | ATT&CK technique | Evidence-based rationale |
|---|---|---|---|---|
| C2 domain/IP detection | DNS/Proxy | Command and Control | T1071 (example) | Outbound comms to known C2 infrastructure |

### Expected output
At least 4 completed rows with rationale.

---

## Step 8, SPL vs ES|QL comparison report
### Goal
Produce an evidence-based cross-platform analysis.

Answer all:
1. Which platform enabled faster hunting iteration and why?
2. Which platform made correlation simpler and why?
3. Which query language is more maintainable for your team?
4. What precision differences did you observe?
5. What performance differences did you observe?
6. What is your recommendation for production use in this scenario?

### Quality requirements
- Use measured evidence (counts, query behavior, screenshots).
- Avoid generic claims.
- Tie conclusions to your actual results.

---

## Step 9, Final QA before submission
Check each item:
- [ ] IOC detections complete in both SPL and ES|QL
- [ ] Behavioral detections complete in both SPL and ES|QL
- [ ] Correlation detections complete in both SPL and ES|QL
- [ ] Kibana checklist completed
- [ ] ATT&CK mapping included
- [ ] One-page comparison included
- [ ] Evidence attached
- [ ] Queries readable and commented

---

## 9) Recommended timeline
- Environment + schema mapping: 25 minutes
- IOC detection: 20 minutes
- Behavioral detection: 35 minutes
- Artifact detection: 15 minutes
- Correlation detection: 30 minutes
- Kibana tasks: 25 minutes
- ATT&CK + report writing: 25 minutes
- Final QA and packaging: 10 minutes

Total: ~3 hours 5 minutes

---

## 10) Troubleshooting quick actions

### If no data appears
1. Expand time picker.
2. Re-check index/index pattern.
3. Ask instructor for exact dataset name.

### If only one platform works
1. Compare field names with your mapping table.
2. Check missing/null fields.
3. Verify query syntax is for the correct platform.

### If results are too noisy
1. Add stricter process conditions.
2. Add parent-process conditions.
3. Filter obvious benign software-updater patterns.

### If correlation returns nothing
1. Validate each signal separately.
2. Widen window to 60m.
3. Re-test and narrow down again.

---

## 11) Submission packaging suggestion
```
submission/
  queries/
    spl/
      ioc.spl
      behavior.spl
      correlation.spl
    esql/
      ioc.esql
      behavior.esql
      correlation.esql
  evidence/
    kibana-discover-*.png
    correlation-results-*.csv
  report/
    comparison.md
    attack-mapping.md
```

---

## 12) Mini submission template (copy/paste)

### Environment
- Splunk instance:
- Kibana space:
- Time range:

### IOC results summary
- Hosts:
- Users:
- First seen:
- Last seen:

### Behavioral results summary
- Query tuning changes:
- Before count:
- After count:

### Correlation summary
- Window used:
- Correlated hosts:
- Why high confidence:

### ATT&CK mappings
- (paste table)

### SPL vs ES|QL comparison
- Precision:
- Performance:
- Maintainability:
- Recommendation:

---

## Final note
Strong detection engineering work is clear, testable, and explainable.
If someone else cannot run your logic and reproduce your conclusions, it is not finished.

Be precise. Be evidence-driven. Keep it operational.
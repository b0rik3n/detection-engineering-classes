# Extended Student Handout (Very Beginner-Friendly)
## OT / ICS / SCADA Detection Engineering Lab

## Read this first
This handout is written for students who are **not highly technical yet**.
You can follow it step-by-step even if this is your first time using Splunk or Kibana.

If you get stuck, do not panic. Use the troubleshooting sections in each step.

---

## 1) What this class is about
In this class, you act like a security analyst who is investigating suspicious activity in an industrial environment.

You will use two tools:
- **Splunk** (query language: SPL)
- **Elastic/Kibana** (query language: ES|QL)

Your job is to find suspicious patterns in logs and show evidence.

---

## 2) Big picture objective (simple version)
You need to do 3 types of detections in **both platforms**:
1. **IOC detections**: known bad values (bad IP, bad domain, etc.)
2. **Behavior detections**: suspicious actions (writes/programming to controllers)
3. **Correlation detections**: combine multiple suspicious signals into one strong alert

At the end, you compare Splunk vs Elastic and explain differences.

---

## 3) Quick glossary (plain English)
- **OT**: Operational Technology. Systems that run physical processes (plants, utilities, industrial lines).
- **ICS/SCADA**: Industrial control systems and monitoring/control layers.
- **PLC**: Programmable logic controller, device that controls machinery/processes.
- **HMI**: Human-machine interface (operator screen).
- **IOC**: Indicator of compromise, known suspicious value.
- **Behavioral detection**: detection based on suspicious activity pattern.
- **Correlation**: requiring multiple suspicious signals together.
- **False positive**: alert that looks bad but is actually normal.
- **Tuning**: adjusting detections to reduce false positives.
- **ATT&CK for ICS**: framework to map observed behavior to known adversary techniques.

---

## 4) Scenario context
This lab is inspired by public OT/ICS reporting patterns (especially suspicious control/protocol write behavior and engineering workstation misuse).

Training references:
1. https://hub.dragos.com/report/frostygoop-ics-malware-impacting-operational-technology
2. https://www.dragos.com/blog/protect-against-frostygoop-ics-malware-targeting-operational-technology

Important: Your class data is synthetic, but designed to resemble real incident patterns.

---

## 5) What you must submit
You must submit all of these:
1. IOC detections in Splunk and ES|QL
2. Behavioral detections in Splunk and ES|QL
3. Correlation detections in Splunk and ES|QL
4. Kibana evidence (screenshots or exported results)
5. ATT&CK for ICS mapping table
6. One-page comparison (Splunk vs ES|QL)

---

## 6) Files you will use
Inside this lab folder, open:
- `splunk/starter-queries.spl`
- `elastic/esql/starter-queries.esql`
- `kibana/checklist.md`
- `data/events.jsonl`

Create a notes file named `my-lab-notes.md` with these headings:
- Environment setup
- Field mapping
- IOC results
- Behavioral results
- Correlation results
- Kibana evidence
- ATT&CK mapping
- Final comparison

---

## 7) Step-by-step, from start to finish

## Step 0: Confirm your environment is working
### Goal
Make sure both tools can see the dataset before doing real work.

### Splunk click-by-click
1. Open Splunk URL from your instructor.
2. Log in.
3. Click **Search & Reporting**.
4. In the top search bar, paste:
   `index=ot_demo | head 20`
5. Set time picker (top right) to a wide range (for example, **All time**).
6. Press Enter.

Expected: You should see rows/events.

### Kibana click-by-click
1. Open Kibana URL from your instructor.
2. Log in.
3. Left menu → **Analytics** → **Discover**.
4. Pick index pattern like `ot_demo_*`.
5. Set time range to include all events.
6. In query bar, use `*` and click refresh.

Expected: You should see rows with `@timestamp`.

### If this fails
- Check time range first.
- Verify index name with instructor.
- Refresh page and retry.

### Record in notes
- Splunk URL/workspace
- Kibana space/index pattern
- Time range used

---

## Step 1: Understand the data fields (very important)
### Goal
Know which field in Splunk corresponds to which field in Elastic.

### Splunk action
Run:
`index=ot_demo | head 50`

Look for fields related to:
- host/user
- protocol/action
- source/destination IP
- domain

### Kibana action
In Discover, inspect fields and values for the same events.

### Build a field mapping table
Copy this into your notes and fill it:

| Meaning | Splunk field | Elastic field |
|---|---|---|
| Host name | host | host.name |
| Username | user | user.name |
| Source IP | src_ip | source.ip |
| Destination IP | dest_ip | destination.ip |
| Protocol | protocol | network.protocol |
| Function code | function_code | ics.function_code |
| ICS action | action | ics.action |
| Domain | domain | domain |

### Why this matters
If your fields are wrong, your detections will silently fail.

---

## Step 2: IOC detections
### Goal
Find direct matches to known suspicious indicators.

### IOC values for this lab
- `185.244.25.12`
- `update-plc-service.net`
- `a9d4c6f2f3f02ea248fbb7b24f6a9b9f`

### Splunk steps
1. Open `splunk/starter-queries.spl`.
2. Copy the first IOC query.
3. Paste into Splunk and run.
4. Sort by time ascending.

Expected: at least one hit with suspicious external destination.

### ES|QL steps
1. Open `elastic/esql/starter-queries.esql`.
2. Copy first IOC block.
3. Run in Kibana ES|QL editor.

Expected: similar IOC hits.

### Record
- impacted hosts
- first seen and last seen
- which IOC types matched (IP/domain/hash)

### Beginner check
If Splunk has results but ES|QL does not, check field names first.

---

## Step 3: Behavioral detections
### Goal
Detect suspicious ICS actions even if IOC changes in future.

### What suspicious behavior means here
- Write/program actions over industrial protocol (Modbus/S7/DNP3)
- Example suspicious actions:
  - write register
  - write coil
  - program download
  - logic write

### Splunk steps
1. In `splunk/starter-queries.spl`, copy behavioral query.
2. Run it.
3. Review hosts/users/protocol/actions.

### ES|QL steps
1. In `elastic/esql/starter-queries.esql`, run behavioral query.
2. Confirm equivalent behavior appears.

### Tuning for beginners
If too many results:
- Filter to engineering workstation hosts only.
- Require specific suspicious actions.
- Exclude read-only protocol actions.

### Record
- final query used in both tools
- how many results before tuning
- how many results after tuning
- what filters you added

---

## Step 4: Correlation detection (high confidence)
### Goal
Only alert when multiple suspicious things happen together.

Required combined pattern:
1. Engineering workstation context
2. Suspicious ICS write/program action
3. Suspicious outbound communication

### Splunk steps
1. Run correlation query from starter SPL.
2. Confirm hosts where all 3 conditions are true in same 30-minute window.

### ES|QL steps
1. Run correlation query in ES|QL starter.
2. Confirm similar correlated results.

### Why correlation matters
Single event can be noisy. Multiple signals together are much more trustworthy.

### Record
- correlated hosts
- time bucket/window used
- short explanation why this is high confidence

### Extra exercise
Test with 15m vs 60m window and compare how alert count changes.

---

## Step 5: Kibana practical work
### Goal
Show that you can investigate and operationalize detections in Elastic.

Use `kibana/checklist.md` and complete all items.

### Discover pivot flow (do this in order)
1. Find suspicious engineering workstation event.
2. Pivot to nearby ICS write/program events.
3. Pivot to outbound suspicious destination.
4. Capture screenshots.

### Create Elastic rules (beginner click path)
1. Left menu → **Security**.
2. Open **Rules**.
3. Click **Create rule**.
4. Choose query rule type.
5. Paste IOC query, configure severity, save.
6. Repeat for behavioral query.
7. Repeat for correlation query.

### Record
- rule names
- severity levels
- schedule interval
- one-sentence triage note per rule

---

## Step 6: ATT&CK for ICS mapping
### Goal
Map what you detected to ATT&CK-style behavior categories.

Use this table:

| Detection | Evidence field(s) | ATT&CK tactic | ATT&CK technique | Why this mapping fits |
|---|---|---|---|---|
| Suspicious outbound domain/IP | destination.ip, domain | Command and Control | (choose best fit) | Known suspicious external comms |

Create at least 4 rows.

Tip: Focus on behavior evidence, not just buzzwords.

---

## Step 7: Final 1-page comparison
Answer clearly:
1. Which platform was easier for IOC detection and why?
2. Which platform was easier for behavior/correlation and why?
3. Which platform felt faster for investigation pivots?
4. What false positives did you see and how did you tune them?
5. What is your recommendation for production use?

Keep it practical and evidence-based.

---

## 8) What “good work” looks like
A strong submission has:
- working queries in both platforms,
- evidence screenshots/exports,
- clear tuning decisions,
- ATT&CK mapping with reasoning,
- and a concrete platform recommendation.

---

## 9) Troubleshooting cheat sheet

### Problem: no results
- Fix time range first.
- Verify index/index pattern name.
- Re-run simple `head` query.

### Problem: results too noisy
- Add stricter action filters.
- Scope to engineering workstations.
- Exclude read-only control traffic.

### Problem: correlation returns zero
- Validate IOC, behavior, and network queries individually first.
- Increase window to 60m temporarily.
- Check field mapping between SPL and ECS.

### Problem: Splunk and ES|QL don’t match
- Compare field names carefully.
- Check data types and null handling.
- Ensure same time range in both tools.

---

## 10) Suggested timeline (3-hour class)
- Setup + field mapping: 30 min
- IOC detection: 25 min
- Behavioral detection: 35 min
- Correlation detection: 30 min
- Kibana practical: 30 min
- ATT&CK + final write-up: 30 min

---

## 11) Copy/paste submission template

### Student name:
### Date:

### Environment
- Splunk index:
- Kibana index pattern:
- Time range:

### IOC summary
- Hosts:
- First seen:
- Last seen:
- IOC types matched:

### Behavioral summary
- Final Splunk query notes:
- Final ES|QL query notes:
- Tuning changes:

### Correlation summary
- Window used:
- Correlated hosts:
- Confidence explanation:

### Kibana evidence
- Screenshot list:
- Rule names + severities:

### ATT&CK mapping
- (insert table)

### SPL vs ES|QL conclusion
- Precision:
- Performance:
- Maintainability:
- Recommendation:

---

## Final reminder
You do not need to be perfect. You need to be clear, methodical, and evidence-driven.
That is real detection engineering.
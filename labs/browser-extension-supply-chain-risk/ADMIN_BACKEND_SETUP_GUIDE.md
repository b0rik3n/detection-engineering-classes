# Admin Backend Setup Guide (Step-by-Step)
## browser-extension-supply-chain-risk

This guide is for the instructor/admin to prepare this lab before class.

## 1) What you need before starting
- Splunk admin or power-user access
- Kibana admin or power-user access
- This repo checked out locally
- Lab data file path: labs/browser-extension-supply-chain-risk/data/events.jsonl

## 2) Splunk setup (click-by-click)
1. Sign in to Splunk Web.
2. Click Settings in the top menu.
3. Click Indexes.
4. Click New Index.
5. Create index named: browser_demo
6. Save.
7. Go to Search and Reporting.
8. Open Add Data (or ask your Splunk admin to ingest JSONL file).
9. Upload file: labs/browser-extension-supply-chain-risk/data/events.jsonl
10. Set sourcetype to match starter query assumptions (or keep JSON default and adapt query fields).
11. Complete import.

### Splunk validation
Run this query:
index=browser_demo | head 20

Expected result: events appear with timestamp and host/user fields.

---

## 3) Kibana and Elastic setup (click-by-click)
1. Sign in to Kibana.
2. Open left menu and go to Stack Management.
3. Open Data Views.
4. Click Create data view.
5. Data view pattern: browser_demo_*
6. Timestamp field: @timestamp
7. Save.

### Data ingestion options
Use your standard ingest method (Elastic Agent, file upload, Logstash, or API).
Import file: labs/browser-extension-supply-chain-risk/data/events.jsonl
Target index should match data view pattern: browser_demo_*

### Kibana validation
1. Go to Analytics then Discover.
2. Select data view: browser_demo_*
3. Set time range to include all imported events.
4. Enter query: *
5. Click Refresh.

Expected result: events are visible.

---

## 4) Query validation
### Splunk
1. Open file: labs/browser-extension-supply-chain-risk/splunk/starter-queries.spl
2. Copy IOC query and run.
3. Copy behavioral query and run.
4. Copy correlation query and run.

### ES|QL
1. Open file: labs/browser-extension-supply-chain-risk/elastic/esql/starter-queries.esql
2. In Kibana, open ES|QL editor.
3. Run IOC query.
4. Run behavioral query.
5. Run correlation query.

Expected result: all three query types return data.

---

## 5) Security rules setup in Kibana (click-by-click)
1. Open Security in the left menu.
2. Click Rules.
3. Click Create rule.
4. Create rule number 1 with IOC query.
5. Create rule number 2 with behavioral query.
6. Create rule number 3 with correlation query.
7. For each rule, set severity, schedule, and a short triage note.
8. Save all rules.

---

## 6) Student readiness checklist
- [ ] Splunk index exists and has data
- [ ] Kibana data view exists and has data
- [ ] SPL starter queries run
- [ ] ES|QL starter queries run
- [ ] Kibana rules page accessible
- [ ] Student handout links are correct

---

## 7) Fast troubleshooting
### No events in Splunk
- Verify index name is exactly: browser_demo
- Widen time range
- Re-check ingestion source

### No events in Kibana
- Verify data view pattern is: browser_demo_*
- Verify timestamp field is @timestamp
- Widen time range

### ES|QL query errors
- Check field names vs dataset
- Fix null or missing fields in query

### Correlation query empty
- Validate IOC and behavioral queries individually first
- Widen correlation window from 30m to 60m for test

---

## 8) Class-day run order (recommended)
1. 10 minutes: tool readiness check
2. 15 minutes: scenario intro
3. 20 minutes: IOC detections
4. 25 minutes: behavioral detections
5. 25 minutes: correlation detections
6. 20 minutes: Kibana rules and evidence
7. 15 minutes: ATT and CK mapping plus write-up

# Admin Backend Setup Guide
## Detection Engineering Classes

This guide is for instructors/admins setting up backend data and tools before class.

## 1) Prerequisites
- Splunk instance with Search & Reporting access
- Elastic/Kibana instance with Discover + Security Rules access
- Ability to create indexes / data views
- A student-facing account or SSO access flow

## 2) Repository layout
All classes live under:
- `labs/<class-name>/`

Each class includes:
- `data/events.jsonl`
- `splunk/starter-queries.spl`
- `elastic/esql/starter-queries.esql`
- `exercise/student-handout-extended.md`
- `instructor/walkthrough-step-by-step.md`

## 3) Splunk backend setup (per class)
1. Create index (example):
   - `cloud_demo`, `ransomware_demo`, `exchange_demo`, etc.
2. Ingest `labs/<class>/data/events.jsonl` into matching index.
3. Validate:
   - `index=<class_index> | head 20`
4. Confirm fields are searchable (`host`, `user`, `src_ip`, `dest_ip`, `domain`, `action`).

## 4) Elastic/Kibana backend setup (per class)
1. Ingest JSONL into index prefix:
   - `<class_index>_*` (example: `cloud_demo_events`)
2. Create data view in Kibana for that prefix.
3. Validate in Discover:
   - query `*` returns events
4. Validate ES|QL from starter file runs without errors.

## 5) Standard class runbook
For each class:
1. Distribute `exercise/student-handout-extended.md`
2. Keep `instructor/walkthrough-step-by-step.md` for live teaching
3. Ensure students can access both Splunk and Kibana
4. Require outputs in both SPL and ES|QL

## 6) Student account model
Recommended:
- Shared read-only data access
- Per-student saved searches/rules namespace if supported
- No production datasets mixed with class datasets

## 7) Data safety controls
- Use synthetic data only for class delivery
- Keep class indexes isolated from production indexes
- Disable outbound connectors/automations in training tenant unless needed

## 8) Validation checklist before class starts
- [ ] All class indexes exist
- [ ] JSONL data loaded into correct index
- [ ] Splunk starter queries run
- [ ] ES|QL starter queries run
- [ ] Kibana rules area accessible
- [ ] Student handout links verified

## 9) Troubleshooting quick reference
- No results in Splunk: wrong index or time range
- No results in Kibana: wrong data view or time range
- ES|QL errors: wrong field names or missing mappings
- Too much noise: tighten behavior filters in starter queries

## 10) Scaling to multiple classes
- Keep one index per class scenario
- Keep one data view per class prefix
- Reuse the same teaching workflow across labs
- Version all content updates in git before class day

## 11) Recommended cadence
- T-2 days: load/validate data
- T-1 day: dry-run instructor walkthrough
- T-0: open student handouts and run readiness checks
- Post-class: collect feedback, tune data + starter queries

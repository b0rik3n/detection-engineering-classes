# de-lab-npm-supply-chain

Practical detection engineering lab where students build equivalent detections in **Splunk SPL** and **Elastic ES|QL** and compare tradeoffs.

## Learning objective
Build, validate, and tune detections across two platforms using the same attack scenario and telemetry.

## Structure
- `exercise/` student instructions and tasks
- `data/` shared synthetic logs (JSONL)
- `splunk/` SPL starter queries
- `elastic/esql/` ES|QL starter queries
- `kibana/` Discover/dashboard/rule checklist
- `instructor/` answer key, expected timeline, grading rubric

## Scenario summary
npm supply-chain compromise leading to postinstall execution, persistence artifacts, and C2 traffic.


# Instructor Walkthrough (Step-by-Step)
## Kubernetes Runtime Threats

## Class flow (suggested 2h 30m)
- 15m intro
- 20m data familiarization
- 25m IOC detections
- 30m behavioral detections
- 25m correlation detections
- 20m Kibana rule creation
- 15m ATT&CK + report wrap-up

## Instructor demo sequence
1. Run baseline query:
   - 
     index=k8s_demo | head 20
2. Show field mapping in Splunk and Kibana side-by-side.
3. Run IOC starter query and explain each result column.
4. Run behavioral query and show one false positive tuning pass.
5. Run correlation query and explain confidence boost from multi-signal logic.
6. In Kibana, create one sample rule end-to-end.

## Expected student checkpoints
- Checkpoint 1: events visible in both tools
- Checkpoint 2: IOC results match across tools
- Checkpoint 3: behavioral query tuned
- Checkpoint 4: correlation produces high-confidence shortlist
- Checkpoint 5: rule metadata includes triage notes

## Common blockers + fixes
- Wrong time picker: force all-time or explicit date range
- Wrong index pattern: verify lab index prefix
- Query pasted in wrong editor mode: KQL vs ES|QL confusion
- Overly broad logic: add action/process constraints

## Grading shortcuts
- Fast fail if no parity between SPL and ES|QL
- Give partial credit for good reasoning even with imperfect syntax
- Prioritize evidence-backed tuning decisions

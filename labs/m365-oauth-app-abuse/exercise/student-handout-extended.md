# Extended Student Handout (Very Beginner-Friendly)
## M365 OAuth App Abuse

## Read this first
This is a click-by-click guide for students who are not very technical yet.
Follow each step in order and record your outputs.

## Step 0: Open tools
### Splunk
1. Open Splunk in browser.
2. Click **Search & Reporting**.
3. Set time to **All time**.
4. Run: 
   
   index=m365_demo | head 20

### Kibana
1. Open Kibana in browser.
2. Go to **Analytics > Discover**.
3. Select index pattern: *
4. Set time to include all events.
5. Run query: *

If either tool shows no events, check index name and time range first.

## Step 1: Field mapping
Map Splunk fields to ECS fields:
- host -> host.name
- user -> user.name
- src_ip -> source.ip
- dest_ip -> destination.ip
- action -> event.action
- process_name -> process.name
- process_commandline -> process.command_line

## Step 2: IOC detection
1. Open 
   splunk/starter-queries.spl
2. Copy IOC query and run in Splunk.
3. Open 
   elastic/esql/starter-queries.esql
4. Copy IOC query and run in Kibana ES|QL.
5. Record impacted hosts and first/last seen times.

## Step 3: Behavioral detection
1. Run behavioral query in Splunk.
2. Run behavioral query in ES|QL.
3. Tune filters to reduce noise.
4. Record before/after counts.

## Step 4: Correlation detection
1. Run correlation query in Splunk (30-minute window).
2. Run correlation query in ES|QL (30-minute window).
3. Record hosts that satisfy all required conditions.

## Step 5: Kibana rule creation (click-by-click)
1. Go to **Security > Rules**.
2. Click **Create rule**.
3. Create IOC rule.
4. Create behavioral rule.
5. Create correlation rule.
6. Set severity and short triage notes.

## Step 6: ATT&CK mapping
Create at least 4 ATT&CK mappings with one-line rationale each.

## Step 7: Final write-up
Write one page comparing SPL vs ES|QL:
- precision
- performance
- maintainability
- recommendation

## Submission checklist
- [ ] IOC queries complete
- [ ] Behavioral queries complete
- [ ] Correlation queries complete
- [ ] Kibana evidence attached
- [ ] ATT&CK mapping attached
- [ ] Final comparison attached

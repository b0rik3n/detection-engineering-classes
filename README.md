# detection-engineering-classes

Central repo for detection engineering classes.

## Labs (in this repo)

- `labs/mucaro-scout`
- `labs/unc1069-crypto-ai-social-engineering-20260430-2046`
- `labs/iran-cyber-risk-escalation-20260430-2055`
- `labs/notepad-plus-plus-supply-chain-20260430-2101`

## Mucaro Scout preload

With Mucaro Scout running locally, preload all source-separated lab logs into Scout SQLite:

```bash
scripts/preload-scout-labs.sh
```

Defaults:

- API URL: `http://localhost:8000`
- Clears existing Scout SQLite events first
- Skips `combined.jsonl` files to avoid duplicate events

Overrides:

```bash
API_URL=http://localhost:8000 CLEAR_FIRST=false scripts/preload-scout-labs.sh
```

## Admin docs

- `ADMIN_BACKEND_SETUP_GUIDE.md`

## Suggested naming convention

- `de-lab-<topic>`

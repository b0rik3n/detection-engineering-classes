# detection-engineering-classes

Central repo for detection engineering classes.

## Labs (in this repo)

- `labs/mucaro-scout`
- `labs/unc1069-crypto-ai-social-engineering-20260430-2046`
- `labs/iran-cyber-risk-escalation-20260430-2055`
- `labs/notepad-plus-plus-supply-chain-20260430-2101`

## Minimum requirements

For the default Mucaro Scout lab stack:

- OS: Ubuntu 22.04/24.04, Debian 12, RHEL 9, Rocky/Alma 9, CentOS Stream 9, or Fedora
- CPU: 2 cores minimum, 4 cores recommended
- RAM: 6GB minimum, 8GB recommended
- Disk: 25GB free minimum, 40GB recommended
- Network: internet access for Docker image pulls and GitHub clone
- Permissions: sudo-capable user

Notes:

- Scout itself is lightweight, but OpenSearch Dashboards is heavier.
- Optional Splunk requires more resources: 8GB RAM minimum, 12GB+ recommended.
- The installer checks CPU/RAM/disk and warns if the host is under minimum.

## Quick install: Mucaro Scout

For Ubuntu/Debian or RHEL-family systems:

```bash
curl -fsSL https://raw.githubusercontent.com/b0rik3n/detection-engineering-classes/main/scripts/install-mucaro-scout.sh | bash
```

The installer will:

- install Docker and the Docker Compose plugin
- clone this repo
- start Mucaro Scout with Docker Compose
- preload source-separated lab logs into Scout SQLite

After install, open:

- Scout UI: `http://localhost:5173`
- Scout API health: `http://localhost:8000/health`
- SQLite health: `http://localhost:8000/health/sqlite`
- OpenSearch Dashboards: `http://localhost:5601`

Optional overrides:

```bash
PRELOAD_LABS=false bash scripts/install-mucaro-scout.sh
START_SPLUNK=true bash scripts/install-mucaro-scout.sh
INSTALL_DIR=$HOME/detection-engineering-classes bash scripts/install-mucaro-scout.sh
MIN_MEM_GB=4 MIN_DISK_GB=15 bash scripts/install-mucaro-scout.sh
```

## Mucaro Scout preload only

With Mucaro Scout already running locally, preload all source-separated lab logs into Scout SQLite:

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

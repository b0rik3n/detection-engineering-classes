# Kibana / Discover checklist

- Set time range to All time.
- Search for malicious updater indicators.
- Add columns for `process.name`, `url.full`, `destination.ip`, `file.name`, `malware.family`, and `mutex.name`.
- Build a timeline from updater request to download to execution to module load/mutex/C2.
- Save at least one IOC-based and one behavior-based detection query.

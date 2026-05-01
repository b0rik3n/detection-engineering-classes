# Student exercise

## Task 1: Identify malicious updater activity
Search for `GUP.exe`, `WinGUp`, `update.exe`, and malicious update URLs.

## Task 2: Confirm network delivery
Search for `45.76.155.202`, `45.77.31.210`, and `45.32.144.255` in proxy/firewall telemetry.

## Task 3: Identify infection chain variant
Search for `EnumWindowStationsW`, `Cobalt Strike Beacon`, `BluetoothService.exe`, and `log.dll`.

## Task 4: Hunt Chrysalis evidence
Search for `Chrysalis` and `Global\Jdhfv_1.0.1`.

## Task 5: Write detections
Create detections for unusual GUP.exe writes/downloads, DLL sideloading by Bitdefender-signed binaries outside Program Files, Chrysalis mutex creation, and outbound C2 beaconing.

## Deliverable
Submit a report with affected users/hosts, timeline, indicators, detection logic, and remediation recommendations.

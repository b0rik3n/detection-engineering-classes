# Instructor answer key

## Core story

A compromised Notepad++ update path selectively delivers malicious update manifests and `update.exe`. Students should identify malicious updater activity, network delivery, Lua/Cobalt Strike and DLL-sideload/Chrysalis variants, mutex evidence, and C2 beaconing.

## Must-find indicators

- `Lotus Blossom`
- `GUP.exe`, `WinGUp`, `update.exe`
- `45.76.155.202, 45.77.31.210, 45.32.144.255`
- `http://45.76.155.202/update/update.exe, http://45.32.144.255/update/update.exe`
- `BluetoothService.exe`, `log.dll`
- `Chrysalis`, `Cobalt Strike Beacon`
- `Global\Jdhfv_1.0.1`
- `EnumWindowStationsW`

## Good detections

- `GUP.exe` downloading or writing unusual files to temp paths
- Bitdefender-signed process outside Program Files loading `log.dll`
- Chrysalis mutex creation
- Cobalt Strike or Chrysalis beaconing to listed C2 IPs
- Lua injection markers such as `EnumWindowStationsW`

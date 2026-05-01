# de-lab-notepad-plus-plus-supply-chain-20260430-2101

Detection engineering lab based on Unit 42's **Nation-State Actors Exploit Notepad++ Supply Chain**.

Timestamped class name: `notepad-plus-plus-supply-chain-20260430-2101`

## Scenario

Between June and December 2025, attackers associated with `Lotus Blossom` compromised infrastructure used by the `Notepad++` updater ecosystem. Targeted users received malicious update manifests and downloaded `update.exe`. Two infection chains are represented in this lab: a Lua script injection variant leading to `Cobalt Strike Beacon`, and DLL sideloading using a renamed Bitdefender component, `BluetoothService.exe`, to load `log.dll` and execute the `Chrysalis` backdoor.

## Known indicators and behaviors

- Threat actor: `Lotus Blossom`
- Application: `Notepad++`
- Updater: `WinGUp`, `GUP.exe`
- Malicious installer: `update.exe`
- C2/download IPs: `45.76.155.202, 45.77.31.210, 45.32.144.255`
- Download URLs: `http://45.76.155.202/update/update.exe, http://45.32.144.255/update/update.exe`
- DLL sideloading: `BluetoothService.exe` loads `log.dll`
- Malware: `Chrysalis`, `Cobalt Strike Beacon`
- Mutex: `Global\Jdhfv_1.0.1`
- Lua API marker: `EnumWindowStationsW`

## Structure

- `data/` source-separated synthetic logs
- `exercise/` student workflow
- `splunk/` starter searches
- `elastic/esql/` starter queries
- `kibana/` checklist
- `instructor/` answer key

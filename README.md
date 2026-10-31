# WinGuardian

A host-based change monitor and malware detector for Windows. On first launch it records a **baseline**
of the system — every file under `C:\Windows` (size, timestamp, SHA-256), every running executable,
every registered service and driver, and every autostart ("persistence") location — and from then on
reports anything that differs from it, checks new executables against malware databases, and lets you
quarantine or trust what it finds.

## Architecture

```
┌──────────────────────────────┐   named pipe (JSON)   ┌──────────────────────────┐
│ WinGuardian.Service          │ ◄──────────────────► │ WinGuardian.Tray         │
│  Windows Service, LocalSystem│  \\.\pipe\           │  notification-area icon, │
│  - MonitorWorker (main loop) │  WinGuardian.Control  │  balloon alerts,         │
│  - FileWatcherService        │                       │  dashboard, settings     │
│  - ReputationWorker          │                       └──────────────────────────┘
│  - SelfProtection            │
│  - PipeServer                │
└──────────────┬───────────────┘
               │ uses
┌──────────────▼───────────────┐
│ WinGuardian.Core             │   C:\ProgramData\WinGuardian\  (SYSTEM + Administrators only)
│  File/Process/Service/       │ ─►  winguardian.db  SQLite: baseline, events, trust list,
│  Persistence monitors, ETW,  │                     quarantine index, reputation cache, settings
│  reputation, quarantine      │     Quarantine\     encoded quarantined files
└──────────────────────────────┘
```

## What it detects

| What | How | When |
|---|---|---|
| Files added / modified / removed | SHA-256 compared to baseline | Real time (FileSystemWatcher) + full rescan every 24h |
| New executables running | Kernel process-start events via **ETW** (parent + command line), polling as fallback | Real time — catches processes that live only milliseconds |
| Suspicious command lines | Rules for download-and-execute PowerShell, encoded commands, certutil/mshta/regsvr32/rundll32 abuse, shadow-copy deletion, Defender tampering, log clearing | Every process start, even for known programs |
| Services & drivers | `HKLM\SYSTEM\CurrentControlSet\Services` (ImagePath, ServiceDll, start type, account) | Every 30s |
| Scheduled tasks | Full task + COM handler investigation (see below) | Real time + every 30s |
| Ports & firewall | New listening ports per program, firewall rule changes, firewall switched off | Every 5s |
| Persistence | Run/RunOnce (machine + every logged-on user), startup folders, WMI event subscriptions, Winlogon, AppInit/AppCert DLLs, LSA packages, BootExecute, IFEO debuggers, SilentProcessExit, Active Setup | Every 30s |
| Known malware | SHA-256 lookups on **MalwareBazaar** and **VirusTotal** for new/changed executables, new processes, and the binaries behind new services/persistence entries | Queued, cached, rate limited |
| Tampering with WinGuardian | Service stopped or killed while Windows was running; program files changed; its own service config changed; another process grabbing its pipe | Startup + real time |
| Digital signatures | Authenticode check (embedded signature **and** Windows security catalogs) of every executable an event is about | With each event |

Events are scored **Info / Low / Medium / High**. The tray pops a notification for Medium and above, and the
icon turns yellow (Medium) or red (High) until alerts are acknowledged.

| Icon | Meaning |
|---|---|
| Green shield | Monitoring, nothing unacknowledged |
| Blue shield `…` | Scan in progress |
| Yellow / red `!` | Unacknowledged Medium / High alerts (red also = service identity could not be verified) |
| Grey `?` | Service not running — **protection is off** (a notification is shown when this happens) |

## Scheduled task & COM handler analysis

Every scheduled task (`C:\Windows\System32\Tasks`) is recorded at baseline and re-investigated whenever its
definition, its COM registration or the program it runs changes. For each task WinGuardian records:

- **Configuration** — author, description, enabled/hidden state, the account it runs as (SYSTEM, a user, a
  group) and run level, triggers, and every action (program + arguments + working directory, or COM handler).
- **What actually runs** — programs are resolved like Windows does (quotes, environment variables, the system
  PATH, `rundll32`/`regsvr32` → the DLL). COM handlers are resolved through the registry *without* creating the
  object: 64-bit and 32-bit (WOW6432Node) registrations, `InprocServer32` / `LocalServer32` / AppID
  `LocalService`, `TreatAs` redirections (cycle-safe, depth-limited), .NET `CodeBase` assemblies, and per-user
  registrations in `HKU\<SID>_Classes` that shadow the machine-wide class (COM hijacking).
- **Trust of that code** — Authenticode signature (embedded or catalog), SHA-256, and whether non-admin
  accounts can modify/replace it, or create it if it is missing ("phantom" targets).
- **What changed** — task file hash, then a field-by-field comparison: metadata only, schedule timing only,
  run-as account, triggers, enabled/hidden, actions, COM registration, and target file content.

Task XML is parsed with DTDs and external entities disabled; nothing is ever executed or instantiated.

**Noise control.** Windows rewrites the start time of repeating tasks by itself (e.g.
`\Microsoft\Windows\Flighting\OneSettings\RefreshCache`); timing-only rewrites update the record silently.
A task that still resolves to the same Microsoft-signed code scores as Info.

**Scoring** is additive and configurable (`Guardian:TaskRiskWeights` overrides any weight in
`TaskRiskScorer.DefaultWeights`; thresholds `TaskRiskMediumThreshold`/`TaskRiskHighThreshold`; tasks running as
SYSTEM or elevated get a `TaskRiskPrivilegedMultiplierPercent` multiplier). Examples: a COM class re-pointed at a
DLL outside Windows/Program Files for a SYSTEM task is High even if the task XML never changed; a new task
running an encoded PowerShell command is High; an unsigned program in a user folder is Medium; a missing program
in a folder ordinary users can write to is flagged as plantable. Every event lists the indicators behind its
score, and says when there was no earlier version to compare with.

**Details window.** Double-click an event for a full report plus expandable sections (task configuration,
executable/COM details, signature, registry registration, previous vs current, threat assessment, modifying
process), with **Copy Details** and **Export JSON**.

**Which process made the change.** The task file is always written by the Task Scheduler service itself, so
file monitoring cannot tell who asked. Windows records the requesting process in Security events 4698–4702, but
only when *Other Object Access Events* auditing is on (off by default). Tick **"Record which process creates or
changes scheduled tasks"** in Settings to enable it; WinGuardian then reports the process ID, path, parent,
start time, signer, command line (from its ETW history) and user. Without auditing, the Task Scheduler
operational log may still give the user; otherwise the report says **Unknown** rather than guessing. COM
registry and program-file changes are not attributed (that would need registry/file SACL auditing).

**Permissions.** Runs inside the service (LocalSystem): reading all task files, all users' loaded registry
hives, and the Security event log requires SYSTEM/administrator rights. Changing the audit policy is done by
the service, only when you opt in.

**Limitations.** Per-user COM overrides are only visible for users whose registry hive is loaded (logged on).
Tasks hidden by tampering with the registry `TaskCache` (without a file in `System32\Tasks`) are not covered.

## Firewall tab (ports, connections, firewall)

Dashboard → **Firewall** shows, refreshed every 5 seconds:

- **Listening Ports** — every TCP/UDP (IPv4/IPv6) port open for incoming traffic: address, port, program, PID,
  the Windows **services** hosted in that process (e.g. `RpcSs` inside `svchost.exe`), signature, path and when
  WinGuardian first saw that program listen there.
- **Active Connections** — every TCP connection with local/remote endpoints, state, program, services, signature.
- **Connection History (24h)** — which program talked to which remote address/port, first/last seen and how
  often (sampled every 5 s, so it also captures connections that are gone by the time you look).
- **Firewall Rules** — every Windows Defender Firewall rule (local and Group Policy) with readable names,
  direction, action, ports, program/service and profiles.

Filter box, sortable columns, colour coding (yellow = unsigned program, red = unsigned program in a
user-writable folder), and right-click: copy, show only this program, open file location, look up the hash.

**Alerts**
- A program starts **listening on a new port**: Info if Microsoft-signed, Low for other signed programs, Medium
  if unsigned, High if unsigned and running from a user folder; one step lower if only reachable from this PC
  (loopback). Ports in Windows' dynamic range (49152+) are tracked per program, so random high ports don't spam.
- **Firewall rules added, changed or removed** — a new rule that lets other computers connect in is Medium
  (Info/Low for Microsoft/validly signed programs, High for an unsigned program in a user folder).
- **Firewall turned off** for any profile, or the firewall service stopped — High (Tamper).

Data comes from the kernel's TCP/UDP tables (`GetExtendedTcpTable`/`GetExtendedUdpTable`), the Service Control
Manager, and the firewall's registry store — no packet capture, so the overhead is negligible. Very short-lived
connections (under ~5 s) can be missed by sampling.

## Signature-aware scoring

Every file, process, service and autostart event for an executable includes its signature status
(shown in the dashboard's *Signature* column). Most files that ship with Windows have no embedded
signature and are signed through security catalogs, so both are checked. Scoring rules:

- **Microsoft-signed** content is routine: changed system files (e.g. Windows Update) drop to Low, and new
  Microsoft programs running from the Windows folder are Info.
- **Validly signed by another publisher**: at most Medium.
- **Unsigned**: keeps its location-based score (e.g. an unsigned new DLL in System32 is High).
- **Signature broken** (file modified after signing): always High.
- Programs running from user-writable folders are never fully routine, even when signed — a renamed copy
  of a Microsoft binary is still validly signed.
- Services/autostart entries that launch a script host (`cmd`, `powershell`, `mshta`, `rundll32`, …) are not
  downgraded for being Microsoft-signed, since the signature says nothing about the command they run. Changes
  to existing entries never drop below Medium.
- VirusTotal quota is not spent on Microsoft-signed files (MalwareBazaar is still checked).

## Responding to alerts

Right-click an event in the dashboard:

- **Acknowledge Selected** — mark as reviewed.
- **Trust…** — stop alerting on it in future. Depending on the event: this file path, everything in its
  folder, this exact file content (hash), this service, this autostart entry, or — for command-line
  detections — *this behaviour when started by this parent program* (e.g. a tool you use that runs
  PowerShell with `-EncodedCommand`), or everything validly signed by this publisher. Manage the list on the
  **Trusted Items** tab.
- **Quarantine File…** — terminates any process running it and moves it into the quarantine folder
  (XOR-encoded with a random per-file key, so it can't run). Files in use are copied and deleted at the next
  reboot. Core Windows files and WinGuardian's own files are refused. The **Quarantine** tab can restore a
  file (its path is then trusted) or delete it permanently.
- **Look Up Hash Online** / **Open in VirusTotal** — check the file's reputation on demand.

Acknowledged events are deleted after the retention period (default 90 days, set in Settings); anything
older than a year is removed regardless.

## Hash reputation (API keys)

Open **Settings…** from the tray menu (UAC prompt) and enter either or both keys:

- **MalwareBazaar** (abuse.ch) — free key from <https://auth.abuse.ch/>. A hit means a confirmed malware sample.
  Used for every new/changed executable, including bulk file changes.
- **VirusTotal** — free key from your VirusTotal account (4 lookups/minute, 500/day). Reported as malicious when
  3+ engines agree, suspicious for 1–2. To protect the daily quota it is used for new processes,
  services, persistence entries and manual lookups, not for every changed file (e.g. during Windows Update).

Optionally enable **auto-quarantine** of files confirmed as known malware.
Keys are stored in the protected database, never in `appsettings.json`.

## Security model

- The service runs as **LocalSystem**; its data folder is restricted to SYSTEM and Administrators.
- Any signed-in user can *read* status, events, the trust list and the quarantine list. Every action that
  changes something (acknowledge, trust, quarantine, restore, settings, rebuild baseline) requires an
  *elevated* administrator — the service impersonates the caller to check — so malware running as you can't
  silently clear its own alerts or trust itself. The tray relaunches itself through UAC for these.
- The tray verifies that the process serving the pipe is the one the Service Control Manager started; if not,
  it shows a red icon and a warning instead of trusting it. The service also detects if another process had
  already created its pipe when it started.
- If the service is stopped or killed while Windows is running, a High tamper alert is raised when it comes
  back, and the tray shows a "protection is off" notification immediately. `install.ps1` sets a short-lived
  maintenance marker so upgrades are reported as Info instead.

## Build & install

Requires the .NET 10 SDK.

```powershell
dotnet build WinGuardian.slnx

# From an elevated PowerShell:
.\scripts\install.ps1            # publishes to C:\Program Files\WinGuardian, registers + starts the service, adds tray autostart
.\scripts\uninstall.ps1          # add -RemoveData to also delete the database and quarantine
```

### Tests

```powershell
dotnet test --project tests\WinGuardian.Tests      # run elevated to include the COM registry tests
```

The suite uses throwaway task folders, temporary databases and uniquely named test COM registrations
(removed afterwards); Microsoft's own tasks are only ever read. Without elevation the HKLM registry tests are
skipped.

Re-running `install.ps1` upgrades in place and keeps the baseline. After upgrading from 0.1, the
persistence baseline is captured automatically on first start.

### Running from a console (development)

From an elevated prompt you can run the service as a normal console app. `WINGUARDIAN_DATA_DIR` keeps
test databases away from the real one, and any setting can be overridden on the command line. Because a
console-run service isn't the registered service, set `WINGUARDIAN_ALLOW_UNVERIFIED_SERVER=1` for the tray
to accept it (this only applies when the real service isn't installed/running).

```powershell
$env:WINGUARDIAN_DATA_DIR = "$env:TEMP\wg-test"
dotnet run --project src\WinGuardian.Service -- --Guardian:ScanRoots:0=C:\SomeTestFolder --Guardian:WatchRoots:0=C:\SomeTestFolder
```

## Configuration

`appsettings.json` next to the service exe, section `Guardian` (restart the service after editing):

| Setting | Default | Notes |
|---|---|---|
| `ScanRoots` | `%WINDIR%` | Trees included in the baseline and full rescans |
| `WatchRoots` | `%WINDIR%` | Trees watched in real time |
| `ExcludedPaths` | logs, temp, registry hives, caches… | Volatile locations that would only generate noise |
| `ExcludedExtensions` | `.log .etl .tmp .evtx .pf .blf .regtrans-ms` | |
| `MaxHashFileSizeMB` | 256 | Larger files are tracked by size/timestamp only |
| `HashThreads` | 4 | Parallel hashing during full scans |
| `ProcessPollSeconds` / `ServicePollSeconds` / `PersistencePollSeconds` | 5 / 30 / 30 | |
| `FullScanIntervalHours` | 24 | |

API keys, auto-quarantine and event retention are set from the tray's **Settings** window instead.

## Known limitations (planned work)

- Windows Update still produces (Low-severity) file events for every changed file; they are recorded but
  do not trigger notifications.
- Signature revocation is not checked (no network access during verification).
- Expect some Low-severity "new executable" events in the first days as occasionally-used Windows
  programs run for the first time since the baseline.
- Per-user autostart entries are only visible while that user is logged on (their registry hive is loaded).
- A user's first logon after install is baselined silently for that user's registry locations.
- An administrator can still stop the service; WinGuardian detects and reports this but cannot prevent it.

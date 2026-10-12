# MDE Live Response Triage Collector

A single, self-contained PowerShell script for forensic triage collection
through **Microsoft Defender for Endpoint (MDE) Live Response**. Upload it to
the Live Response library, run it on a Windows device, and pull back one zip of
timeline-relevant forensic artefacts (artifacts) - no binaries to upload.

**The problem it solves:**

- **`getfile` is one file at a time**, with no wildcards or folders. Pulling
  event logs, Prefetch, registry hives, LNK files, JumpLists and browser
  history for every user means hundreds of individual `getfile` commands. This
  script gathers them into one zip in a single `run`, so you need one `getfile`
  (plus a short, printed list of ready-to-paste commands for the few locked
  files it can't read).
- **The built-in investigation package falls short for timelining.** Defender's
  *Collect investigation package* is a point-in-time snapshot of system state
  (processes, services, network connections, autoruns), much of it exported as
  text or CSV rather than raw artefacts. It omits key timeline sources such as
  registry hives, Amcache, SRUM, LNK files, JumpLists, browser history and most
  event logs. This script collects those raw, ready for your own parsers.

It is a **lightweight, best-effort first pass**, for when all you have is a Live
Response session. It uses ordinary file reads only, with **no Volume Shadow
Copy and no raw disk access**. It copies what Windows lets it open and moves
on, so locked files and NTFS metafiles are not in the zip (see [What it can't collect](#what-it-cant-collect)).

For a comprehensive collection, including locked files and raw NTFS
artefacts, use a full collector such as KAPE or the Velociraptor Offline
Collector.

## Approach

A deliberately small, timeline-oriented triage set rather than a full sweep:

- **Timeline value first.** Artefacts are chosen for timestamped evidence of
  execution, file access, persistence, device use, browsing and command-line
  activity.
- **Windows-native sources.** Third-party application artefacts are out of
  scope; mainstream browser history is the exception.
- **Metadata over payload.** E.g. `$I` records rather than `$R` content, `.wer`
  reports rather than dumps, keeping the zip practical to pull over Live
  Response.

Everything is collected raw, for processing with your usual parsers and
timeline tooling.

## Behaviour

- **Requirements:** Windows PowerShell 5.1.
- **Best effort.** Anything that can't be read is skipped and counted in the
  summary; the run never stops on an error. There is no log file.
- **Locked files.** Files are opened with shared read access, so in-use files
  are copied where Windows allows it. Files held exclusively are skipped (see
  [What it can't collect](#what-it-cant-collect)).
- **Single pass.** Files are streamed straight into the zip
  (`System.IO.Compression`, fastest compression) with no temporary copies.
- **Output location.** `C:\LiveResponse\`, marked Hidden + System to keep it
  out of the user's view. Each run adds a new `<HOSTNAME>_<UTC timestamp>Z.zip`.
  The folder is queued for deletion at the next reboot.
- **Footprint.** Writes the output folder, the zip and one
  `PendingFileRenameOperations` value; nothing is downloaded or installed.
  Queuing the deletion compiles a small helper (`Add-Type`), so `csc.exe`
  runs: expect transient files in `%TEMP%` and Prefetch/Amcache entries for
  `csc.exe` (and usually `cvtres.exe`).

## Quick start

1. In the Defender portal, upload `collector.ps1` to the Live Response library.
2. Open a Live Response session on the device and run:
   ```
   run collector.ps1
   ```
3. When it finishes, it prints the zip's path. Retrieve it with the command it
   gives you:
   ```
   getfile "C:\LiveResponse\<HOSTNAME>_<yyyyMMdd_HHmmss>Z.zip"
   ```
4. If it lists **Additional inaccessible artefacts**, those are files PowerShell
   could not open (e.g. `$MFT`, `$LogFile`, locked hives). Copy and paste the
   printed `getfile` lines into the same session to retrieve them directly via
   the Defender sensor.

The script is unsigned. Either enable *Allow unsigned script execution* in the
Live Response settings for your tenant, or sign it with your own code-signing
certificate (re-sign after every change).

## What it collects

These are the locations it attempts. Anything locked is skipped (see below).
`<user>` means every folder under `C:\Users`.
Service accounts (SYSTEM, LocalService, NetworkService) are not `<user>`: their
locations are listed explicitly, with `<sysprof>` meaning
`C:\Windows\System32\config\systemprofile`. Paths are resolved from
`%SystemDrive%`, so non-`C:` installs work too. Inside the zip, files keep their
original path (e.g. `C/Windows/Prefetch/...`).

| Category | Artefact | Location |
|---|---|---|
| **Logs** | EVTX | `C:\Windows\System32\winevt\logs\*.evtx` |
| | Defender Logs | `C:\ProgramData\Microsoft\Windows Defender\Support\` and `...\Scans\History\Service\DetectionHistory\` (recursive), `...\Scans\History\Service\Detections.log`, `C:\Windows\Temp\MpCmdRun.log` |
| | Firewall Log | `C:\Windows\System32\LogFiles\Firewall\pfirewall.*` |
| | SetupAPI | `C:\Windows\INF\setupapi*.log` |
| **Execution** | Prefetch | `C:\Windows\Prefetch\*.pf` |
| | AppCompat PCA | `C:\Windows\appcompat\pca\*` |
| | SRUM | `C:\Windows\System32\SRU\` (recursive: `SRUDB.dat` and its ESE logs) |
| | .NET CLR Usage Logs | `*.log` under `<user>\AppData\Local\Microsoft\CLR_*\` and `<sysprof>\AppData\Local\Microsoft\CLR_*\` |
| | PowerShell History | `*_history.txt` in `<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\`, and the same under `<sysprof>` (System32 and SysWOW64) |
| | PowerShell Transcripts | `PowerShell_transcript.*.txt` in `<user>\Documents\` and `<user>\OneDrive*\Documents\` (and their `20*` dated subfolders), `C:\Windows\{System32,SysWOW64}\*\`, `C:\PSTranscript\20*\`; a policy transcription folder on a local drive (recursive) |
| **Registry** | System hives | `SAM`, `SECURITY`, `SOFTWARE`, `SYSTEM` in `C:\Windows\System32\config\` and `config\RegBack\` (plus `SYSTEM1`); `C:\Windows\AppCompat\Programs\Amcache.hve` |
| | User hives | `<user>\NTUSER.DAT`, `<user>\AppData\Local\Microsoft\Windows\UsrClass.dat`; service accounts: `C:\Windows\System32\config\DEFAULT`, `<sysprof>\NTUSER.DAT`, `C:\Windows\ServiceProfiles\{LocalService,NetworkService}\NTUSER.DAT` |
| | Transaction logs | `.LOG1`/`.LOG2` alongside each hive above |
| **Persistence** | Scheduled Tasks | `C:\Windows\{System32,SysWOW64}\Tasks\`; PowerShell scheduled jobs in `<user>\AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\` and the same under `<sysprof>` (all recursive) |
| | BITS | `C:\ProgramData\Microsoft\Network\Downloader\` (recursive) |
| | Startup Folders | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\`, `<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` (recursive) |
| **File and folder access** | LNK | `<user>\AppData\Roaming\Microsoft\Windows\Recent\*.lnk`, `<user>\AppData\Roaming\Microsoft\Office\Recent\` (recursive), `<user>\Desktop\*.lnk`, `Start Menu\Programs\*.lnk` (user and `C:\ProgramData`, top level) |
| | JumpLists | `<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms`, `...\Recent\CustomDestinations\*.customDestinations-ms` |
| | Recycle Bin | `C:\$Recycle.Bin\<SID>\$I*` |
| | File History | `<user>\AppData\Local\Microsoft\Windows\FileHistory\Configuration\Catalog*.edb` |
| **Browsing** | Chromium-based: Edge and Chrome (incl. Beta, Dev, Canary), Chromium, Brave, Vivaldi, Opera, Yandex, Arc, Coc Coc, QQ Browser, 360 Secure Browser, Wave Browser, Prisma Access Browser, Supermium | `History*` (360: `360History*`) in each browser's `User Data\<profile>\` under `<user>`; Chrome channels, Chromium, Prisma Access, Supermium and Wave also under `<sysprof>` |
| | Firefox | `<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>\places.sqlite*` |
| **Crashes** | WER | `*.wer` under `C:\ProgramData\Microsoft\Windows\WER\` and `<user>\AppData\Local\Microsoft\Windows\WER\` |

## What it can't collect

Without VSS or raw disk access, some high-value artefacts cannot be read. They
appear in the summary as *Not accessible*. Where the Defender sensor can fetch
them, the script prints a ready-to-paste `getfile` command at the end.

| Artefact | Why | Retrieval |
|---|---|---|
| `$MFT` | NTFS metafile | `getfile` (printed) |
| `$LogFile` | NTFS metafile | `getfile` (printed) |
| `$UsnJrnl:$J` | NTFS metafile (ADS) | Not possible via `getfile`; needs a raw-NTFS collector |
| System hives (`SAM`, `SECURITY`, `SOFTWARE`, `SYSTEM`) and their transaction logs | Held exclusively by the kernel while loaded | `getfile` for the hives (printed) |
| SRUM (`SRUDB.dat`) | Often held open by the system (collected when it isn't) | `getfile` (printed) |
| Service account hives (`DEFAULT`, LocalService and NetworkService `NTUSER.DAT`) and their transaction logs | Loaded while Windows runs | `getfile` for the hives (printed) |
| User hives of logged-on users (`NTUSER.DAT`, `UsrClass.dat`) and their transaction logs | Held exclusively while the user is logged on | `getfile` manually (not printed, to keep the list short) |

Hives of users who are not logged on, and most other in-use files (EVTX, a
running browser's History), are collected normally.

## Example output

A Live Response run on a workstation (hostname changed); counts depend on the
host.

```
C:\> run collector.ps1
Transcript started, output file is C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Temp\PSScriptOutputs\PSScript_Transcript_{7A927308-4292-462A-853C-A1A9054005D6}.txt
Live Response collector v0.16.0
Host WS042, started 2026-10-12T07:56:16Z
[01/24] Collecting $LogFile
[02/24] Collecting $MFT
[03/24] Collecting $UsnJrnl:$J
[04/24] Collecting AppCompat PCA
[05/24] Collecting BITS
[06/24] Collecting Defender Logs
[07/24] Collecting EVTX
[08/24] Collecting Firewall Log
[09/24] Collecting Prefetch
[10/24] Collecting Registry Hives (system)
[11/24] Collecting Scheduled Tasks
[12/24] Collecting SetupAPI
[13/24] Collecting SRUM
[14/24] Collecting Browser History
[15/24] Collecting File History
[16/24] Collecting JumpLists
[17/24] Collecting LNK
[18/24] Collecting .NET CLR Usage Logs
[19/24] Collecting PowerShell History
[20/24] Collecting PowerShell Transcripts
[21/24] Collecting Recycle Bin ($I)
[22/24] Collecting Registry Hives (user)
[23/24] Collecting Startup Folders
[24/24] Collecting WER

Artefact summary:
  $LogFile                 Not accessible
  $MFT                     Not accessible
  $UsnJrnl:$J              Not accessible
  AppCompat PCA            3 collected
  BITS                     10 collected
  Defender Logs            20 collected
  EVTX                     255 collected
  Firewall Log             Missing
  Prefetch                 427 collected
  Registry Hives (system)  3 collected, 12 not accessible
  Scheduled Tasks          312 collected
  SetupAPI                 15 collected
  SRUM                     19 collected
  Browser History          2 collected
  File History             Missing
  JumpLists                46 collected
  LNK                      483 collected
  .NET CLR Usage Logs      2 collected
  PowerShell History       Missing
  PowerShell Transcripts   Missing
  Recycle Bin ($I)         233 collected
  Registry Hives (user)    15 collected, 15 not accessible
  Startup Folders          2 collected
  WER                      494 collected

Collected 2343 files total (188.76 MB)
Retrieve with: getfile "C:\LiveResponse\WS042_20261012_075616Z.zip"

Additional inaccessible artefacts (locked from PowerShell - retrieve directly in this Live Response session):
getfile "C:\$LogFile"
getfile "C:\$MFT"
getfile "C:\Windows\System32\config\SAM"
getfile "C:\Windows\System32\config\SECURITY"
getfile "C:\Windows\System32\config\SOFTWARE"
getfile "C:\Windows\System32\config\SYSTEM"
getfile "C:\Windows\System32\config\DEFAULT"
getfile "C:\Windows\ServiceProfiles\LocalService\NTUSER.DAT"
getfile "C:\Windows\ServiceProfiles\NetworkService\NTUSER.DAT"
```

Status meanings: **N collected** (copied into the zip), **Not accessible** (the
file exists but could not be read), **Missing** (not present on this host).
Browser History counts browser profiles, not files.

## License

[0BSD](LICENSE) (Zero-Clause BSD): use it for anything, no attribution
required. Provided as is, with no warranty. Test it in your environment before
relying on it in an investigation.

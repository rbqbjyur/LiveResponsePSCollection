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
`<user>` means every folder in the profiles directory, normally `C:\Users`
(service profiles under `C:\Windows` are not included). Paths are resolved from `%SystemDrive%`, so
non-`C:` installs work too. Inside the zip, files keep their original path
(e.g. `C/Windows/Prefetch/...`).

| Category | Artefact | Location |
|---|---|---|
| **Logs** | EVTX | `C:\Windows\System32\winevt\logs\*` |
| | Firewall Log | `C:\Windows\System32\LogFiles\Firewall\pfirewall*.log` |
| | SetupAPI | `C:\Windows\INF\setupapi*.log` |
| **Execution** | Prefetch | `C:\Windows\Prefetch\*.pf` |
| | SRUM | `C:\Windows\System32\SRU\SRUDB.dat` |
| | PowerShell History | `<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` |
| | PowerShell Transcripts | `PowerShell_transcript.*.txt` in `<user>\Documents\` and `<user>\OneDrive*\Documents\` (and their dated subfolders); a policy transcription folder on a local drive (recursive) |
| **Registry** | System hives | `SAM`, `SECURITY`, `SOFTWARE`, `SYSTEM` in `C:\Windows\System32\config\`; `C:\Windows\AppCompat\Programs\Amcache.hve` |
| | User hives | `<user>\NTUSER.DAT`, `<user>\AppData\Local\Microsoft\Windows\UsrClass.dat` |
| | Transaction logs | `.LOG1`/`.LOG2` alongside each hive above |
| **Persistence** | Scheduled Tasks | `C:\Windows\System32\Tasks\` (recursive) |
| | Startup Folders | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\`, `<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` |
| **File and folder access** | LNK | `<user>\AppData\Roaming\Microsoft\Windows\Recent\*.lnk` |
| | JumpLists | `<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms` |
| | Recycle Bin | `C:\$Recycle.Bin\<SID>\$I*` |
| | File History | `<user>\AppData\Local\Microsoft\Windows\FileHistory\Configuration\Catalog*.edb` |
| **Browsing** | Edge, Chrome | `<user>\AppData\Local\{Microsoft\Edge,Google\Chrome}\User Data\<profile>\History*` |
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
| User hives of logged-on users (`NTUSER.DAT`, `UsrClass.dat`) and their transaction logs | Held exclusively while the user is logged on | `getfile` manually (not printed, to keep the list short) |

Hives of users who are not logged on, and most other in-use files (EVTX, a
running browser's History), are collected normally.

## Example output

A Live Response run on a workstation with one logged-on user (plus the
`Default` profile); counts depend on the host.

```
C:\> run collector.ps1
Live Response collector v0.15.0
Host WS042, started 2026-10-10T10:52:53Z
[01/20] Collecting $LogFile
[02/20] Collecting $MFT
[03/20] Collecting $UsnJrnl:$J
[04/20] Collecting EVTX
[05/20] Collecting Firewall Log
[06/20] Collecting Prefetch
[07/20] Collecting Registry Hives (system)
[08/20] Collecting Scheduled Tasks
[09/20] Collecting SetupAPI
[10/20] Collecting SRUM
[11/20] Collecting Browser History
[12/20] Collecting File History
[13/20] Collecting JumpLists
[14/20] Collecting LNK
[15/20] Collecting PowerShell History
[16/20] Collecting PowerShell Transcripts
[17/20] Collecting Recycle Bin ($I)
[18/20] Collecting Registry Hives (user)
[19/20] Collecting Startup Folders
[20/20] Collecting WER

Artefact summary:
  $LogFile                 Not accessible
  $MFT                     Not accessible
  $UsnJrnl:$J              Not accessible
  EVTX                     438 collected
  Firewall Log             Missing
  Prefetch                 448 collected
  Registry Hives (system)  3 collected, 12 not accessible
  Scheduled Tasks          263 collected
  SetupAPI                 10 collected
  SRUM                     1 collected
  Browser History          1 collected
  File History             Missing
  JumpLists                42 collected
  LNK                      63 collected
  PowerShell History       1 collected
  PowerShell Transcripts   Missing
  Recycle Bin ($I)         9 collected
  Registry Hives (user)    3 collected, 6 not accessible
  Startup Folders          3 collected
  WER                      218 collected

Collected 1504 files total (55.31 MB)
Retrieve with: getfile "C:\LiveResponse\WS042_20261010_105253Z.zip"

Additional inaccessible artefacts (locked from PowerShell - retrieve directly in this Live Response session):
getfile "C:\$LogFile"
getfile "C:\$MFT"
getfile "C:\Windows\System32\config\SAM"
getfile "C:\Windows\System32\config\SECURITY"
getfile "C:\Windows\System32\config\SOFTWARE"
getfile "C:\Windows\System32\config\SYSTEM"
```

Status meanings: **N collected** (copied into the zip), **Not accessible** (the
file exists but could not be read), **Missing** (not present on this host).
Browser History counts browser profiles, not files.

## License

[0BSD](LICENSE) (Zero-Clause BSD): use it for anything, no attribution
required. Provided as is, with no warranty. Test it in your environment before
relying on it in an investigation.

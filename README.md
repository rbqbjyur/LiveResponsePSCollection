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
- **Full collectors need binaries and supporting files.** Staging KAPE or a
  Velociraptor collector through Live Response means uploading and running
  executables, which is not always possible or permitted. A multi-file toolkit
  can collect more; this script aims to do as much as one script can, for when
  a script is all you can run.
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
  scope; browser history is the exception. Microsoft client logs and metadata
  (Defender, Configuration Manager, OneDrive, Teams) are included.
- **Metadata over content.** E.g. `$I` records rather than the deleted `$R`
  files, `.wer` reports rather than memory dumps, browser history rather than
  caches, keeping the zip practical to pull over Live Response.
- **Legacy forms included.** Older-Windows forms of each artefact (e.g. `.evt`,
  `RecentFileCache.bcf`, XP profile paths) and the previous install kept in
  `Windows.old` after a feature update are collected as part of the same
  artefact, after its current form.

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
  Zip entry times are each file's last-write time in UTC.
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
certificate.

## What it collects

These are the locations it attempts, in the order the script runs them (the
NTFS metafiles that open the summary are covered under
[What it can't collect](#what-it-cant-collect)). Anything locked is skipped.

- `<user>` is every folder under `C:\Users` (and, on XP-era layouts,
  `C:\Documents and Settings`).
- `<sysprof>` is `C:\Windows\System32\config\systemprofile` (the SYSTEM
  account). Service accounts are not `<user>`; their locations are listed
  explicitly.
- `<profile>` is any browser profile folder.
- Within each artefact, locations run from current Windows to legacy forms and
  then `Windows.old`.
- Junctions and symbolic links are not followed; on Windows they only point
  back to folders already covered.
- Paths are resolved from `%SystemDrive%`, so non-`C:` installs work too.
  Inside the zip, files keep their original path (e.g. `C/Windows/Prefetch/...`).

| Artefact | Location |
|---|---|
| Amcache | `C:\Windows\AppCompat\Programs\Amcache.hve`<br>`C:\Windows\AppCompat\Programs\RecentFileCache.bcf` (Windows 7)<br>`C:\Windows.old\Windows\AppCompat\Programs\{Amcache.hve,RecentFileCache.bcf}`<br>hives with their `.LOG1`/`.LOG2` |
| AppCompat PCA | `C:\Windows\appcompat\pca\*` |
| BITS | `C:\ProgramData\Microsoft\Network\Downloader\` (recursive) |
| Defender Logs | `C:\ProgramData\Microsoft\Windows Defender\Support\` (recursive)<br>`C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\` (recursive)<br>`C:\ProgramData\Microsoft\Windows Defender\Scans\History\Service\Detections.log`<br>`C:\Windows\Temp\MpCmdRun.log`<br>`C:\ProgramData\Microsoft\Microsoft AntiMalware\Support\` (recursive; older Defender / SCEP)<br>`C:\Windows.old\Windows\Temp\MpCmdRun.log` |
| Event Logs | `C:\Windows\System32\winevt\logs\*.evtx`<br>`C:\Windows\System32\config\*.evt` (XP)<br>`C:\Windows.old\Windows\System32\winevt\logs\*.evtx` |
| Firewall Log | `C:\Windows\System32\LogFiles\Firewall\pfirewall.*`<br>`C:\Windows.old\Windows\System32\LogFiles\Firewall\pfirewall.*` |
| Group Policy | `C:\Windows\System32\GroupPolicy\` (recursive)<br>`C:\ProgramData\Microsoft\Group Policy\History\` (recursive; cached domain GPOs)<br>`<user>\AppData\Local\Microsoft\Group Policy\History\` (recursive)<br>`C:\Windows.old\Windows\System32\GroupPolicy\` `*.ini`, `*.pol` and `*\Scripts\` (recursive) |
| Prefetch | `C:\Windows\Prefetch\*.pf`<br>`C:\Windows.old\Windows\Prefetch\*.pf` |
| Registry Hives (system) | `C:\Windows\System32\config\{SAM,SECURITY,SOFTWARE,SYSTEM}`<br>`C:\Windows\System32\config\RegBack\{SAM,SECURITY,SOFTWARE,SYSTEM,SYSTEM1}`<br>`C:\System Volume Information\_restore*\RP*\snapshot\_REGISTRY_*` (XP restore points)<br>`C:\Windows.old\Windows\System32\config\` and `...\config\RegBack\`, same hives<br>each with its `.LOG1`/`.LOG2` |
| Restore Point Logs | `C:\System Volume Information\_restore*\RP*\rp.log` (XP) |
| SCCM Client Logs | `C:\Windows\CCM\Logs\*` |
| Scheduled Tasks | `C:\Windows\{System32,SysWOW64}\Tasks\` (recursive)<br>`<user>\AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\` (recursive)<br>`C:\Windows\{System32,SysWOW64}\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\` (recursive)<br>`C:\Windows\Tasks\*.job`, `C:\Windows\SchedLgU.txt` (legacy)<br>`C:\Windows.old\Windows\System32\Tasks\` (recursive), `C:\Windows.old\Windows\Tasks\*.job`, `C:\Windows.old\Windows\SchedLgU.txt` |
| SetupAPI | `C:\Windows\INF\setupapi*.log`<br>`C:\Windows\setupapi.log` (XP)<br>`C:\Windows.old\Windows\INF\setupapi*.log` |
| SRUM | `C:\Windows\System32\SRU\` (recursive: `SRUDB.dat` and its ESE logs)<br>`C:\Windows.old\Windows\System32\SRU\` (recursive) |
| Syscache | `C:\System Volume Information\Syscache.hve`, with its `.LOG1`/`.LOG2` (Windows 7 / Server) |
| User Access Logging (SUM) | `C:\Windows\System32\LogFiles\Sum\` (recursive; Windows Server) |
| Browser History | `<user>\AppData\Local\Microsoft\{Edge,Edge Beta,Edge Dev,Edge SxS}\User Data\<profile>\History*`<br>`<user>\AppData\Local\Google\{Chrome,Chrome Beta,Chrome Dev,Chrome SxS}\User Data\<profile>\History*`<br>`<user>\AppData\Local\{Chromium,Vivaldi,Supermium,WaveBrowser}\User Data\<profile>\History*`<br>`<user>\AppData\Local\BraveSoftware\Brave-Browser\User Data\<profile>\History*`<br>`<user>\AppData\Local\Yandex\YandexBrowser\User Data\<profile>\History*`<br>`<user>\AppData\Local\CocCoc\Browser\User Data\<profile>\History*`<br>`<user>\AppData\Local\Tencent\QQBrowser\User Data\<profile>\History*`<br>`<user>\AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\<profile>\History*`<br>`<user>\AppData\Local\Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data\<profile>\History*`<br>`<user>\AppData\Roaming\Opera Software\Opera Stable\History*` and `...\Opera Stable\<profile>\History*`<br>`<user>\AppData\Roaming\360se6\User Data\<profile>\360History*`<br>`<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>\places.sqlite*`<br>`<sysprof>\AppData\Local\` paths for Chrome (all channels), Chromium, Prisma Access, Supermium and Wave<br>`<user>\AppData\Local\Microsoft\Windows\WebCache\*` (IE 10/11, legacy Edge)<br>`index.dat` under `<user>\AppData\Local\Microsoft\Windows\{History,IEDownloadHistory}\` (recursive; IE 9 and earlier)<br>`<user>\AppData\Roaming\Mozilla\Firefox\Profiles\<profile>\downloads.sqlite*` (Firefox before v26)<br>`<user>\AppData\Roaming\Opera\Opera\{global_history.dat,typed_history.xml}` (Opera 12 and earlier)<br>`<user>\AppData\Roaming\Apple Computer\Safari\History.plist` (Safari for Windows)<br>XP: `<user>\Local Settings\Application Data\` paths for Chrome (all channels), Chromium and Prisma Access; `<user>\Application Data\` paths for Supermium, Firefox (incl. `downloads.sqlite*`), Opera 12 and Safari; `index.dat` under `<user>\Local Settings\History\History.IE5\` (recursive) |
| File History Catalogs | `<user>\AppData\Local\Microsoft\Windows\FileHistory\Configuration\Catalog*.edb` |
| JumpLists | `<user>\AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms`<br>`<user>\AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms` |
| LNK | `<user>\AppData\Roaming\Microsoft\Windows\Recent\*.lnk`<br>`<user>\AppData\Roaming\Microsoft\Office\Recent\` (recursive)<br>`<user>\Desktop\*.lnk`<br>`<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*.lnk`<br>`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\*.lnk`<br>`<user>\Recent\` (recursive; XP)<br>`C:\System Volume Information\_restore*\RP*\*.lnk` (XP restore points) |
| .NET CLR Usage Logs | `<user>\AppData\Local\Microsoft\CLR_*\` (recursive, `*.log`)<br>`<sysprof>\AppData\Local\Microsoft\CLR_*\` (recursive, `*.log`)<br>`C:\Windows.old\Windows\System32\config\systemprofile\AppData\Local\Microsoft\CLR_*\` (recursive, `*.log`) |
| OneDrive Metadata | `<user>\AppData\Local\Microsoft\OneDrive\settings\` (recursive)<br>`<user>\AppData\Local\Microsoft\OneDrive\logs\` (recursive: `*.odl*`, `*.aodl`, `*.loggz`, `*.keystore`; not the `.etlgz` traces)<br>`<user>\AppData\Local\Microsoft\SkyDrive\logs\` (recursive; SkyDrive)<br>`<user>\AppData\Local\Microsoft\Windows\OneDrive\logs\` (recursive; Windows 8.1) |
| PowerShell History | `<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt`<br>`C:\Windows\{System32,SysWOW64}\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt` |
| PowerShell Transcripts | `<user>\Documents\PowerShell_transcript.*.txt` and `<user>\Documents\20*\PowerShell_transcript.*.txt`<br>`<user>\OneDrive*\Documents\PowerShell_transcript.*.txt` and `...\Documents\20*\PowerShell_transcript.*.txt`<br>`C:\Windows\{System32,SysWOW64}\*\PowerShell_transcript.*.txt`<br>`C:\PSTranscript\20*\PowerShell_transcript.*.txt`<br>the policy transcription folder, if on a local drive (recursive) |
| Recycle Bin ($I, INFO2) | `C:\$Recycle.Bin\<SID>\$I*`<br>`INFO2` under `C:\RECYCLE*\` (recursive; XP `RECYCLER`/`RECYCLED`) |
| Registry Hives (user) | `<user>\NTUSER.DAT`<br>`<user>\AppData\Local\Microsoft\Windows\UsrClass.dat`<br>`C:\Windows\System32\config\DEFAULT` (SYSTEM)<br>`<sysprof>\NTUSER.DAT`<br>`C:\Windows\ServiceProfiles\{LocalService,NetworkService}\NTUSER.DAT`<br>`C:\Windows.old\Windows\`, the same four service-account hives<br>each with its `.LOG1`/`.LOG2` |
| Startup Folders | `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\` (recursive)<br>`<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\` (recursive) |
| Teams Logs | `<user>\AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Logs\*`<br>`<user>\AppData\Local\Packages\MicrosoftTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Logs\*` (Windows 11 built-in Teams)<br>`<user>\AppData\Roaming\Microsoft\Teams\logs.txt` (classic Teams) |
| WER | `C:\ProgramData\Microsoft\Windows\WER\` (recursive, `*.wer`)<br>`<user>\AppData\Local\Microsoft\Windows\WER\` (recursive, `*.wer`) |
| Windows Timeline | `ActivitiesCache.db*` under `<user>\AppData\Local\ConnectedDevicesPlatform\` (recursive; Windows 10) |

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
| SRUM (`SRUDB.dat` and its ESE files) | Sometimes held open by the system (collected when it isn't) | `getfile` (printed) |
| Service account hives (`DEFAULT`, LocalService and NetworkService `NTUSER.DAT`) and their transaction logs | Loaded while Windows runs | `getfile` for the hives (printed) |
| User Access Logging `Current.mdb` (servers) | Usually held open by the UAL service | `getfile` (printed) |
| User hives of logged-on users (`NTUSER.DAT`, `UsrClass.dat`) and their transaction logs | Held exclusively while the user is logged on | `getfile` manually (not printed, to keep the list short) |
| `WebCacheV01.dat` of logged-on users | Usually held open in the user's session | `getfile` manually (not printed) |

Hives of users who are not logged on, and most other in-use files (EVTX, a
running browser's History), are collected normally. If any other
machine-wide file turns out to be locked, it is added to the printed `getfile`
list (transaction logs excepted).

## Example output

A Live Response run on a workstation; counts depend on the host.

```
C:\> run collector.ps1
Transcript started, output file is C:\ProgramData\Microsoft\Windows Defender Advanced Threat Protection\Temp\PSScriptOutputs\PSScript_Transcript_{1F421CC2-5B0D-46C5-96C0-1640C7484804}.txt
Live Response collector v1.0.1
Host WS042, started 2026-10-12T10:33:45Z
[01/33] Collecting $LogFile
[02/33] Collecting $MFT
[03/33] Collecting $UsnJrnl:$J
[04/33] Collecting Amcache
[05/33] Collecting AppCompat PCA
[06/33] Collecting BITS
[07/33] Collecting Defender Logs
[08/33] Collecting Event Logs
[09/33] Collecting Firewall Log
[10/33] Collecting Group Policy
[11/33] Collecting Prefetch
[12/33] Collecting Registry Hives (system)
[13/33] Collecting Restore Point Logs
[14/33] Collecting SCCM Client Logs
[15/33] Collecting Scheduled Tasks
[16/33] Collecting SetupAPI
[17/33] Collecting SRUM
[18/33] Collecting Syscache
[19/33] Collecting User Access Logging (SUM)
[20/33] Collecting Browser History
[21/33] Collecting File History Catalogs
[22/33] Collecting JumpLists
[23/33] Collecting LNK
[24/33] Collecting .NET CLR Usage Logs
[25/33] Collecting OneDrive Metadata
[26/33] Collecting PowerShell History
[27/33] Collecting PowerShell Transcripts
[28/33] Collecting Recycle Bin ($I, INFO2)
[29/33] Collecting Registry Hives (user)
[30/33] Collecting Startup Folders
[31/33] Collecting Teams Logs
[32/33] Collecting WER
[33/33] Collecting Windows Timeline

Artefact summary:
  $LogFile                  Not accessible
  $MFT                      Not accessible
  $UsnJrnl:$J               Not accessible
  Amcache                   3 collected
  AppCompat PCA             3 collected
  BITS                      10 collected
  Defender Logs             32 collected
  Event Logs                437 collected
  Firewall Log              Missing
  Group Policy              Missing
  Prefetch                  504 collected
  Registry Hives (system)   Not accessible
  Restore Point Logs        Missing
  SCCM Client Logs          Missing
  Scheduled Tasks           317 collected
  SetupAPI                  12 collected
  SRUM                      7 collected, 3 not accessible
  Syscache                  Missing
  User Access Logging (SUM) Missing
  Browser History           9 collected, 1 not accessible
  File History Catalogs     Missing
  JumpLists                 48 collected
  LNK                       70 collected
  .NET CLR Usage Logs       2 collected
  OneDrive Metadata         3788 collected
  PowerShell History        1 collected
  PowerShell Transcripts    Missing
  Recycle Bin ($I, INFO2)   6 collected
  Registry Hives (user)     27 collected, 15 not accessible
  Startup Folders           3 collected
  Teams Logs                57 collected
  WER                       524 collected
  Windows Timeline          9 collected

Collected 5897 files total (211.99 MB)
Retrieve with: getfile "C:\LiveResponse\WS042_20261012_103345Z.zip"

Additional inaccessible artefacts (locked from PowerShell - retrieve directly in this Live Response session):
getfile "C:\$LogFile"
getfile "C:\$MFT"
getfile "C:\Windows\System32\config\SAM"
getfile "C:\Windows\System32\config\SECURITY"
getfile "C:\Windows\System32\config\SOFTWARE"
getfile "C:\Windows\System32\config\SYSTEM"
getfile "C:\Windows\System32\SRU\SRUDB.dat"
getfile "C:\Windows\System32\SRU\SRUDB.jfm"
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

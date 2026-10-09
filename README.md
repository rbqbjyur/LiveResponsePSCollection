# Live Response collector

A single, self-contained PowerShell script for triage collection through
**Microsoft Defender for Endpoint Live Response**. Upload it to the Live Response
library, run it on a device, and pull back one zip of timeline-relevant Windows
artefacts.

It is a lightweight alternative to full triage collectors for when all you
have is a Live Response session: no agents, binaries or modules are needed.

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

## Example output

Illustrative only; the counts depend on the host.

```
Live Response collector v0.13.4
[01/20] Collecting $LogFile
...
[20/20] Collecting WER

Artefact summary:
  $LogFile                 Not accessible
  $MFT                     Not accessible
  $UsnJrnl:$J              Not accessible
  EVTX                     412 collected
  Firewall Log             Missing
  Prefetch                 238 collected
  Registry Hives (system)  3 collected, 12 not accessible
  ...
  SRUM                     Not accessible
  ...
  WER                      9 collected

Collected 1874 files total (312.4 MB)
Retrieve with: getfile "C:\LiveResponse\WS042_20261009_141503Z.zip"

Additional inaccessible artefacts (locked from PowerShell - retrieve directly in this Live Response session):
getfile "C:\$LogFile"
getfile "C:\$MFT"
getfile "C:\Windows\System32\config\SAM"
getfile "C:\Windows\System32\config\SECURITY"
getfile "C:\Windows\System32\config\SOFTWARE"
getfile "C:\Windows\System32\config\SYSTEM"
getfile "C:\Windows\System32\SRU\SRUDB.dat"
```

Status meanings: **N collected** (copied into the zip), **Not accessible** (the
file exists but could not be read), **Missing** (not present on this host).

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

## What it collects

`<user>` means every profile folder under `C:\Users` (service profiles under
`C:\Windows` are not included). Paths are resolved from `%SystemDrive%`, so
non-`C:` installs work too. Inside the zip, files keep their original path
(e.g. `C/Windows/Prefetch/...`).

| Category | Artefact | Location |
|---|---|---|
| **File system** | `$MFT` | `C:\$MFT` |
| | `$LogFile` | `C:\$LogFile` |
| | `$UsnJrnl:$J` | `C:\$Extend\$UsnJrnl:$J` |
| **Logs** | EVTX | `C:\Windows\System32\winevt\logs\*` |
| | Firewall Log | `C:\Windows\System32\LogFiles\Firewall\pfirewall*.log` |
| | SetupAPI | `C:\Windows\INF\setupapi*.log` |
| **Execution** | Prefetch | `C:\Windows\Prefetch\*.pf` |
| | SRUM | `C:\Windows\System32\SRU\SRUDB.dat` |
| | PowerShell History | `<user>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` |
| | PowerShell Transcripts | `<user>\Documents\PowerShell_transcript.*.txt` |
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

### NTFS metafiles

PowerShell cannot open `$MFT`, `$LogFile` or `$UsnJrnl:$J`, so they are never
in the zip; they always show as *Not accessible* in the summary. The script
prints `getfile` commands for `$MFT` and `$LogFile`, which the Defender sensor
can retrieve directly. `$UsnJrnl:$J` cannot be retrieved with `getfile` and
needs raw-NTFS tooling.

## Behaviour

- **Requirements:** Windows PowerShell 5.1, run via Live Response (as SYSTEM).
- **Best effort.** Anything that can't be read is skipped and counted; the run
  never stops on an error. There is no log file.
- **Locked files.** Files are opened with shared read access, so most in-use
  files (EVTX, a running browser's History) are still copied. Files held
  exclusively are not: on a live system that always includes the loaded system
  hives and usually SRUM. Machine-wide files that fail this way are listed at
  the end as `getfile` commands. **Loaded user hives** (`NTUSER.DAT` /
  `UsrClass.dat` of logged-on users) fail the same way but are not listed, to
  keep the list short; `getfile` them individually if needed.
- **Timestamps.** Zip entries keep only the source file's last-write time. Use
  `$MFT` for full MACB timestamps.
- **Single pass.** Files are streamed straight into the zip
  (`System.IO.Compression`, fastest compression) with no temporary copies.
- **Output location.** `C:\LiveResponse\`, marked Hidden + System to keep it
  out of the user's view. Each run adds a new `<HOSTNAME>_<UTC timestamp>Z.zip`.
  The folder is queued for deletion at the next reboot; delete it sooner
  yourself once you have retrieved the zip.
- **Footprint.** Evidence files are opened read-only. The script writes the
  output folder and zip to the system volume (new `$MFT`/`$UsnJrnl` records,
  possible overwrite of unallocated space) and one `PendingFileRenameOperations`
  value. Running it also leaves the normal traces of PowerShell execution
  (e.g. script block logging, if enabled). Nothing is downloaded or installed.

## License

[MIT](LICENSE). Provided as is, with no warranty. Test it in your environment
before relying on it in an investigation.

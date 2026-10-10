# Changelog

Notable changes to `collector.ps1`. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## 0.15.0 - 2026-10-10

### Added
- PowerShell transcripts from OneDrive-redirected Documents (Known Folder
  Move), from dated subfolders (policy transcription), and from a Group Policy
  transcription `OutputDirectory` on a local drive (Windows PowerShell and
  PowerShell 7).

### Changed
- User profiles are enumerated under the ProfileList `ProfilesDirectory`
  (falls back to `<SystemDrive>\Users`).

## 0.14.0 - 2026-10-10

### Changed
- Artefacts are defined in one table; collection and progress lines now follow
  the summary order.
- Each artefact location is handled independently, so a failure skips only
  that location.
- Zip entry timestamps are written in UTC (previously host local time).
- The host name and UTC start time are printed after the version banner.
- Changelog moved from the script header to this file.

## 0.13.5 - 2026-10-10

### Fixed
- Delete-on-reboot cleanup never took effect: `MoveFileEx` now receives a true
  null destination.

### Changed
- Licence changed from MIT to 0BSD; SPDX identifier added.

## 0.13.4 - 2026-10-09

First version in this repository.

### Changed
- `getfile` follow-ups for `$MFT` and `$LogFile` are printed only if the read
  actually failed.

## 0.1.0 - 0.13.3 (before the repository, undated)

- **0.13.3** - Changed: user profiles are the folders under `\Users`; service
  profiles under `\Windows` are excluded.
- **0.13.2** - Added: `getfile` follow-ups for locked machine-wide files.
  Changed: zip size shown on the "Collected" line.
- **0.13.1** - Changed: all paths anchored to the system drive.
- **0.13.0** - Changed: paths resolved from the environment (non-`C:`
  installs); UTC timestamp in the zip name; approved-verb function names.
- **0.12.2** - Changed: structural tidy, no behaviour change.
- **0.12.1** - Added: per-artefact progress line.
- **0.12.0** - Added: registry transaction logs (`.LOG1`/`.LOG2`) for every
  hive.
- **0.11.0** - Added: File History catalogs.
- **0.10.0** - Added: SetupAPI device-install logs, Windows Firewall log.
- **0.9.0** - Added: `SECURITY` hive, Scheduled Tasks, Startup folders, WER
  report metadata, `$LogFile`.
- **0.8.2** - Changed: end of run prints only runnable commands.
- **0.8.1** - Changed: summary in a fixed three-group order; files streamed
  into the zip in one pass.
- **0.8.0** - Added: Chrome and Firefox history, counted per browser profile.
- **0.7.0** - Added: `$MFT` and `$UsnJrnl:$J` as summary placeholders, with a
  `getfile` command for `$MFT`.
- **0.6.0** - Added: system and user registry hives; zip size.
- **0.5.1** - Added: per-artefact status summary.
- **0.5.0** - Added: EVTX, Prefetch, SRUM, PowerShell history and transcripts.
- **0.4.0** - Added: delete-on-reboot cleanup. Changed: output folder renamed
  to `C:\LiveResponse`.
- **0.3.0** - Changed: zip compression set to Fastest.
- **0.2.0** - Changed: one fixed, hidden output folder instead of one per run.
- **0.1.0** - Initial collector: Recycle Bin `$I`, LNK, JumpLists, Edge
  history.

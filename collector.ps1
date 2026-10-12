# SPDX-License-Identifier: 0BSD
#Requires -Version 5.1

<#
.SYNOPSIS
    Collects timeline-relevant Windows triage artefacts into one zip, for
    retrieval through Microsoft Defender for Endpoint (MDE) Live Response.

.DESCRIPTION
    Upload to the Defender Live Response library and run it on a device. It
    writes <SystemDrive>\LiveResponse\<hostname>_<UTC timestamp>Z.zip, prints a
    per-artefact summary, the getfile command for the zip, and getfile commands
    for locked machine-wide files it could not read.

    Best effort: anything that can't be read is skipped silently and counted in
    the summary; the run never stops on an error. The output folder is queued
    for deletion at the next reboot.

.EXAMPLE
    run collector.ps1

    In a Live Response session, after uploading the script to the library.

.EXAMPLE
    .\collector.ps1

    From an elevated Windows PowerShell 5.1 prompt, e.g. for testing.

.NOTES
    Version: $CollectorVersion below (semver); changes are in CHANGELOG.md.
    Requires Windows PowerShell 5.1; no modules, no network access.
    License: 0BSD.

.LINK
    https://github.com/rbqbjyur/LiveResponsePSCollection
#>

# Every catch {} in this script is deliberate: failures are skipped and the run
# carries on (best effort, no failure log - see the project's design rules).
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '',
    Justification = 'Best-effort collection: unreadable items are skipped silently by design.')]
param()

# ============================== CONFIG ==============================

$CollectorVersion = '1.0.1'

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# Resolve the system drive from the environment so the script is not tied to a C:
# install; every artefact path below is taken relative to it (or to a profile).
$sysDrive = $env:SystemDrive                 # e.g. C:
if (-not $sysDrive) { $sysDrive = [System.IO.Path]::GetPathRoot([Environment]::SystemDirectory).TrimEnd('\') }

$hostName = $env:COMPUTERNAME
# UTC, so the name is unambiguous across time zones; trailing 'Z' marks it as UTC.
$runStart  = (Get-Date).ToUniversalTime()
$timestamp = $runStart.ToString('yyyyMMdd_HHmmss') + 'Z'

# Fixed, low-profile folder that holds the output of every run. Each run drops a
# separately-named zip in here, so repeated collections accumulate side by side.
$outDir  = Join-Path $sysDrive 'LiveResponse'
$zipPath = Join-Path $outDir "${hostName}_${timestamp}.zip"

# Where user profiles live, relative to the system drive: modern first, then
# legacy (XP). Each folder under a root is one profile (see Get-UserProfilePath).
$profileRoots = @('Users', 'Documents and Settings')

# Artefacts to collect: one row per summary line. Add an artefact by adding a row.
#   Name     Summary label.
#   Group    1 = drive root (NTFS metafiles), 2 = other system files, 3 = user-specific.
#   System   Path pattern(s) relative to the system drive.
#   User     Path pattern(s) relative to each user profile.
#   Logs     Also collect each match's registry transaction logs (<file>.LOG1/.LOG2).
#   Literal  Use the path as-is, without listing it. For NTFS metafiles, which
#            PowerShell can neither see nor open: they stay as 'Not accessible'
#            placeholders so future raw/sensor-based collection slots in cleanly.
#   GetFile  Literal rows only: the Defender sensor's getfile can fetch it, so the
#            command is printed at the end if the read failed.
#   CountBy  'Folder' counts one unit per folder holding matches (e.g. per browser
#            profile) instead of one per file.
#   Supporting  CountBy rows: file-name patterns of supporting files (journals,
#            ESE logs). A unit counts as collected only if its main file was read;
#            supporting files alone don't count while a main file is present.
#   RegDirs  Folders named by registry values (Key, Value), each searched with its
#            Pattern. Local drive paths only: shares are skipped (no network access).
# Within a row, patterns run from the modern, standard location to legacy and
# alternative ones: current Windows first, then older Windows forms (Windows 7,
# XP), then the previous install kept in Windows.old after a feature update.
# Legacy forms are part of the same artefact, so they share its summary line.
# Pattern syntax: see Resolve-PathPattern. Collection, progress and summary all
# run in Group order, then by Name alphabetically ignoring non-alphanumerics (e.g.
# the leading '$'). That order is applied at run time, so a row's position in
# this list doesn't matter - but keep it in that order for readability.
$artefacts = @(
    # 1. Drive root: the timeline-relevant NTFS metafiles (the "NTFS Triforce").
    @{ Name = '$LogFile';    Group = 1; Literal = $true; GetFile = $true; System = '$LogFile' }
    @{ Name = '$MFT';        Group = 1; Literal = $true; GetFile = $true; System = '$MFT' }
    @{ Name = '$UsnJrnl:$J'; Group = 1; Literal = $true; System = '$Extend\$UsnJrnl:$J' }   # no getfile route

    # 2. Other system files.
    # Program execution records: Amcache.hve, and its Windows 7 predecessor.
    @{ Name = 'Amcache'; Group = 2; Logs = $true; System = @(
        'Windows\AppCompat\Programs\Amcache.hve'
        'Windows\AppCompat\Programs\RecentFileCache.bcf'                 # Windows 7
        'Windows.old\Windows\AppCompat\Programs\Amcache.hve'
        'Windows.old\Windows\AppCompat\Programs\RecentFileCache.bcf'
    ) }
    # Program Compatibility Assistant execution records (Windows 11 22H2+).
    @{ Name = 'AppCompat PCA'; Group = 2; System = 'Windows\appcompat\pca\*' }
    # BITS job database (qmgr.db) and its ESE logs: downloads and persistence.
    @{ Name = 'BITS';          Group = 2; System = 'ProgramData\Microsoft\Network\Downloader\**\*' }
    # Defender text logs (MPLog etc.) and detection history; not the quarantine
    # (file content). Defender event logs are covered by Event Logs.
    @{ Name = 'Defender Logs'; Group = 2; System = @(
        'ProgramData\Microsoft\Windows Defender\Support\**\*'
        'ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\**\*'
        'ProgramData\Microsoft\Windows Defender\Scans\History\Service\Detections.log'
        'Windows\Temp\MpCmdRun.log'
        'ProgramData\Microsoft\Microsoft AntiMalware\Support\**\*'      # older Defender / SCEP
        'Windows.old\Windows\Temp\MpCmdRun.log'
    ) }
    @{ Name = 'Event Logs'; Group = 2; System = @(
        'Windows\System32\winevt\logs\*.evtx'
        'Windows\System32\config\*.evt'                                  # XP
        'Windows.old\Windows\System32\winevt\logs\*.evtx'
    ) }
    @{ Name = 'Firewall Log'; Group = 2; System = @(                     # logging off by default
        'Windows\System32\LogFiles\Firewall\pfirewall.*'
        'Windows.old\Windows\System32\LogFiles\Firewall\pfirewall.*'
    ) }
    # Group Policy: local policy and scripts, and the cached copies of domain GPOs
    # (incl. Group Policy Preferences XML such as ScheduledTasks.xml) - persistence
    # and deployment evidence.
    @{ Name = 'Group Policy'; Group = 2
       System = @(
           'Windows\System32\GroupPolicy\**\*'
           'ProgramData\Microsoft\Group Policy\History\**\*'
           'Windows.old\Windows\System32\GroupPolicy\*.ini'
           'Windows.old\Windows\System32\GroupPolicy\*.pol'
           'Windows.old\Windows\System32\GroupPolicy\*\Scripts\**\*'
       )
       User = 'AppData\Local\Microsoft\Group Policy\History\**\*' }
    @{ Name = 'Prefetch'; Group = 2; System = @(
        'Windows\Prefetch\*.pf'
        'Windows.old\Windows\Prefetch\*.pf'
    ) }
    # Transaction logs hold un-flushed changes, so Registry Explorer / RegRipper /
    # plaso can replay a dirty hive and recover the most recent entries. RegBack
    # copies are usually empty on current Windows, but older snapshots when present.
    @{ Name = 'Registry Hives (system)'; Group = 2; Logs = $true; System = @(
        'Windows\System32\config\SAM'
        'Windows\System32\config\SECURITY'
        'Windows\System32\config\SOFTWARE'
        'Windows\System32\config\SYSTEM'
        'Windows\System32\config\RegBack\SAM'
        'Windows\System32\config\RegBack\SECURITY'
        'Windows\System32\config\RegBack\SOFTWARE'
        'Windows\System32\config\RegBack\SYSTEM'
        'Windows\System32\config\RegBack\SYSTEM1'
        'System Volume Information\_restore*\RP*\snapshot\_REGISTRY_*'  # XP restore points
        'Windows.old\Windows\System32\config\SAM'
        'Windows.old\Windows\System32\config\SECURITY'
        'Windows.old\Windows\System32\config\SOFTWARE'
        'Windows.old\Windows\System32\config\SYSTEM'
        'Windows.old\Windows\System32\config\RegBack\SAM'
        'Windows.old\Windows\System32\config\RegBack\SECURITY'
        'Windows.old\Windows\System32\config\RegBack\SOFTWARE'
        'Windows.old\Windows\System32\config\RegBack\SYSTEM'
        'Windows.old\Windows\System32\config\RegBack\SYSTEM1'
    ) }
    # XP restore-point logs (rp.log: each restore point's creation time and description).
    @{ Name = 'Restore Point Logs'; Group = 2; System = 'System Volume Information\_restore*\RP*\rp.log' }
    # Configuration Manager (SCCM) client logs; only on ConfigMgr-managed hosts.
    @{ Name = 'SCCM Client Logs';   Group = 2; System = 'Windows\CCM\Logs\*' }
    # XML task definitions, plus PowerShell scheduled jobs (definitions and output).
    @{ Name = 'Scheduled Tasks'; Group = 2
       System = @(
           'Windows\System32\Tasks\**\*'
           'Windows\SysWOW64\Tasks\**\*'
           'Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\**\*'
           'Windows\SysWOW64\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\**\*'
           'Windows\Tasks\*.job'                                         # legacy at.exe / Task Scheduler 1.0
           'Windows\SchedLgU.txt'                                        # legacy Task Scheduler log
           'Windows.old\Windows\System32\Tasks\**\*'
           'Windows.old\Windows\Tasks\*.job'
           'Windows.old\Windows\SchedLgU.txt'
       )
       User = 'AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\**\*' }
    # Device/driver install logs.
    @{ Name = 'SetupAPI'; Group = 2; System = @(
        'Windows\INF\setupapi*.log'
        'Windows\setupapi.log'                                           # XP
        'Windows.old\Windows\INF\setupapi*.log'
    ) }
    # SRUDB.dat plus its ESE logs and checkpoint, for dirty-database recovery.
    @{ Name = 'SRUM'; Group = 2; System = @(
        'Windows\System32\SRU\**\*'
        'Windows.old\Windows\System32\SRU\**\*'
    ) }
    # Syscache.hve: program/file execution data (Windows 7 / Server era).
    @{ Name = 'Syscache'; Group = 2; Logs = $true; System = 'System Volume Information\Syscache.hve' }
    # User Access Logging (Windows Server): clients and users per role, with first
    # and last access times. ESE databases plus their logs, needed to repair them.
    @{ Name = 'User Access Logging (SUM)'; Group = 2; System = 'Windows\System32\LogFiles\Sum\**\*' }

    # 3. User-specific. Service accounts (SYSTEM, LocalService, NetworkService) are
    # not user profiles; where they matter, their paths are listed under System.
    # .NET CLR usage logs: one log per process that loaded the CLR (e.g. .NET tooling).
    @{ Name = '.NET CLR Usage Logs'; Group = 3
       System = @(
           'Windows\System32\config\systemprofile\AppData\Local\Microsoft\CLR_*\**\*.log'
           'Windows.old\Windows\System32\config\systemprofile\AppData\Local\Microsoft\CLR_*\**\*.log'
       )
       User = 'AppData\Local\Microsoft\CLR_*\**\*.log' }
    # Browser history: one pattern per browser (or channel), counted per user x
    # browser x profile. History DB only (plus its journal). Maintained browsers
    # first, then IE / legacy Edge (WebCache, index.dat) and other discontinued
    # browsers or formats, then XP profile paths.
    @{ Name = 'Browser History'; Group = 3; CountBy = 'Folder'
       Supporting = @('*-journal', '*-wal', '*-shm', '*Provider Cache', '*.log', '*.chk', '*.jrs', '*.jfm')
       System = @(
           'Windows\System32\config\systemprofile\AppData\Local\Google\Chrome\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Google\Chrome Beta\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Google\Chrome Dev\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Google\Chrome SxS\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Chromium\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\Supermium\User Data\*\History*'
           'Windows\System32\config\systemprofile\AppData\Local\WaveBrowser\User Data\*\History*'
       )
       User = @(
           'AppData\Local\Microsoft\Edge\User Data\*\History*'                                   # Edge
           'AppData\Local\Microsoft\Edge Beta\User Data\*\History*'                              # Edge Beta
           'AppData\Local\Microsoft\Edge Dev\User Data\*\History*'                               # Edge Dev
           'AppData\Local\Microsoft\Edge SxS\User Data\*\History*'                               # Edge Canary
           'AppData\Local\Google\Chrome\User Data\*\History*'                                    # Chrome
           'AppData\Local\Google\Chrome Beta\User Data\*\History*'                               # Chrome Beta
           'AppData\Local\Google\Chrome Dev\User Data\*\History*'                                # Chrome Dev
           'AppData\Local\Google\Chrome SxS\User Data\*\History*'                                # Chrome Canary
           'AppData\Local\Chromium\User Data\*\History*'                                         # Chromium
           'AppData\Local\BraveSoftware\Brave-Browser\User Data\*\History*'                      # Brave
           'AppData\Local\Vivaldi\User Data\*\History*'                                          # Vivaldi
           'AppData\Roaming\Opera Software\Opera Stable\History*'                                # Opera (single profile)
           'AppData\Roaming\Opera Software\Opera Stable\*\History*'                              # Opera (profiles)
           'AppData\Local\Yandex\YandexBrowser\User Data\*\History*'                             # Yandex
           'AppData\Local\Packages\TheBrowserCompany.Arc_ttt1ap7aakyb4\LocalCache\Local\Arc\User Data\*\History*'   # Arc
           'AppData\Local\CocCoc\Browser\User Data\*\History*'                                   # Coc Coc
           'AppData\Local\Tencent\QQBrowser\User Data\*\History*'                                # QQ Browser
           'AppData\Roaming\360se6\User Data\*\360History*'                                      # 360 Secure Browser
           'AppData\Local\WaveBrowser\User Data\*\History*'                                      # Wave Browser
           'AppData\Local\Palo Alto Networks\PrismaAccessBrowser\User Data\*\History*'           # Prisma Access Browser
           'AppData\Local\Supermium\User Data\*\History*'                                        # Supermium
           'AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite*'                           # Firefox
           'AppData\Local\Microsoft\Windows\WebCache\*'                                          # IE 10/11, legacy Edge
           'AppData\Local\Microsoft\Windows\History\**\index.dat'                                # IE 9 and earlier
           'AppData\Local\Microsoft\Windows\IEDownloadHistory\**\index.dat'                      # IE 9/10 downloads
           'AppData\Roaming\Mozilla\Firefox\Profiles\*\downloads.sqlite*'                        # Firefox < 26 downloads
           'AppData\Roaming\Opera\Opera\global_history.dat'                                      # Opera <= 12
           'AppData\Roaming\Opera\Opera\typed_history.xml'                                       # Opera <= 12
           'AppData\Roaming\Apple Computer\Safari\History.plist'                                 # Safari for Windows
           'Local Settings\Application Data\Google\Chrome\User Data\*\History*'                  # XP: Chrome
           'Local Settings\Application Data\Google\Chrome Beta\User Data\*\History*'             # XP: Chrome Beta
           'Local Settings\Application Data\Google\Chrome Dev\User Data\*\History*'              # XP: Chrome Dev
           'Local Settings\Application Data\Google\Chrome SxS\User Data\*\History*'              # XP: Chrome Canary
           'Local Settings\Application Data\Chromium\User Data\*\History*'                       # XP: Chromium
           'Local Settings\Application Data\Palo Alto Networks\PrismaAccessBrowser\User Data\*\History*'   # XP: Prisma Access
           'Application Data\Supermium\User Data\*\History*'                                     # XP: Supermium
           'Application Data\Mozilla\Firefox\Profiles\*\places.sqlite*'                          # XP: Firefox
           'Application Data\Mozilla\Firefox\Profiles\*\downloads.sqlite*'                       # XP: Firefox < 26 downloads
           'Application Data\Opera\Opera\global_history.dat'                                      # XP: Opera <= 12
           'Application Data\Opera\Opera\typed_history.xml'                                       # XP: Opera <= 12
           'Application Data\Apple Computer\Safari\History.plist'                                 # XP: Safari
           'Local Settings\History\History.IE5\**\index.dat'                                     # XP: IE
       ) }
    # File History catalogs (Catalog1/2.edb): metadata about backed-up files, not
    # the files themselves; only present when File History is enabled.
    @{ Name = 'File History Catalogs'; Group = 3; User = 'AppData\Local\Microsoft\Windows\FileHistory\Configuration\Catalog*.edb' }
    @{ Name = 'JumpLists'; Group = 3; User = @(
        'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms'
        'AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms'
    ) }
    # Shortcuts: recent files, Office recent, desktop and Start Menu (top level only).
    @{ Name = 'LNK'; Group = 3
       System = @(
           'ProgramData\Microsoft\Windows\Start Menu\Programs\*.lnk'
           'System Volume Information\_restore*\RP*\*.lnk'               # XP restore points
       )
       User = @(
           'AppData\Roaming\Microsoft\Windows\Recent\*.lnk'
           'AppData\Roaming\Microsoft\Office\Recent\**\*'
           'Desktop\*.lnk'
           'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*.lnk'
           'Recent\**\*'                                                 # XP
       ) }
    # OneDrive: settings (file lists, sync database) and client activity logs (.odl,
    # .odlgz, .odlsent, .aodl, .loggz) with the .keystore needed to decode their
    # obfuscated strings, then the older SkyDrive and Windows 8.1
    # built-in client locations. Not the ETW traces (.etlgz, bulk), the client's
    # own program files or the synced files.
    @{ Name = 'OneDrive Metadata'; Group = 3; User = @(
        'AppData\Local\Microsoft\OneDrive\settings\**\*'
        'AppData\Local\Microsoft\OneDrive\logs\**\*.odl*'
        'AppData\Local\Microsoft\OneDrive\logs\**\*.aodl'
        'AppData\Local\Microsoft\OneDrive\logs\**\*.loggz'
        'AppData\Local\Microsoft\OneDrive\logs\**\*.keystore'
        'AppData\Local\Microsoft\SkyDrive\logs\**\*'                       # SkyDrive
        'AppData\Local\Microsoft\Windows\OneDrive\logs\**\*'              # Windows 8.1
    ) }
    # PSReadLine history for every host (console, VS Code, ...), including SYSTEM's.
    @{ Name = 'PowerShell History'; Group = 3
       System = @(
           'Windows\System32\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt'
           'Windows\SysWOW64\config\systemprofile\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt'
       )
       User = 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\*_history.txt' }
    # Transcripts go to the user's Documents - possibly moved into OneDrive (Known
    # Folder Move) - directly or, with policy transcription, in date subfolders.
    # Policy can also redirect them to a central folder (Windows PowerShell and PS 7);
    # System lists other places they are commonly found (SYSTEM runs, C:\PSTranscript).
    @{ Name = 'PowerShell Transcripts'; Group = 3
       System = @(
           'Windows\System32\*\PowerShell_transcript.*.txt'
           'Windows\SysWOW64\*\PowerShell_transcript.*.txt'
           'PSTranscript\20*\PowerShell_transcript.*.txt'
       )
       User = @(
           'Documents\PowerShell_transcript.*.txt'
           'Documents\20*\PowerShell_transcript.*.txt'
           'OneDrive*\Documents\PowerShell_transcript.*.txt'
           'OneDrive*\Documents\20*\PowerShell_transcript.*.txt'
       )
       RegDirs = @(
           @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription'; Value = 'OutputDirectory'; Pattern = '**\PowerShell_transcript.*.txt' }
           @{ Key = 'HKLM:\SOFTWARE\Policies\Microsoft\PowerShellCore\Transcription';     Value = 'OutputDirectory'; Pattern = '**\PowerShell_transcript.*.txt' }
       ) }
    # Recycle Bin metadata only ($I records; INFO2 on XP), no deleted-file content.
    @{ Name = 'Recycle Bin ($I, INFO2)'; Group = 3; System = @(
        '$Recycle.Bin\*\$I*'
        'RECYCLE*\**\INFO2'                                              # XP (RECYCLER / RECYCLED)
    ) }
    # User hives, plus the service accounts' hives: DEFAULT is the SYSTEM account's
    # (HKU\.DEFAULT / S-1-5-18), the others LocalService and NetworkService.
    @{ Name = 'Registry Hives (user)'; Group = 3; Logs = $true
       System = @(
           'Windows\System32\config\DEFAULT'
           'Windows\System32\config\systemprofile\NTUSER.DAT'
           'Windows\ServiceProfiles\LocalService\NTUSER.DAT'
           'Windows\ServiceProfiles\NetworkService\NTUSER.DAT'
           'Windows.old\Windows\System32\config\DEFAULT'
           'Windows.old\Windows\System32\config\systemprofile\NTUSER.DAT'
           'Windows.old\Windows\ServiceProfiles\LocalService\NTUSER.DAT'
           'Windows.old\Windows\ServiceProfiles\NetworkService\NTUSER.DAT'
       )
       User = @(
           'NTUSER.DAT'
           'AppData\Local\Microsoft\Windows\UsrClass.dat'
       ) }
    @{ Name = 'Startup Folders'; Group = 3
       System = 'ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\**\*'
       User   = 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\**\*' }
    # Teams client logs only (sign-ins, calls, meetings); no message stores or caches.
    # New Teams (work/school), the Windows 11 built-in Teams, then classic Teams.
    @{ Name = 'Teams Logs'; Group = 3; User = @(
        'AppData\Local\Packages\MSTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Logs\*'
        'AppData\Local\Packages\MicrosoftTeams_8wekyb3d8bbwe\LocalCache\Microsoft\MSTeams\Logs\*'
        'AppData\Roaming\Microsoft\Teams\logs.txt'                              # classic Teams
    ) }
    # WER: only the .wer report metadata, never the crash dumps (bulk binary content).
    @{ Name = 'WER'; Group = 3
       System = 'ProgramData\Microsoft\Windows\WER\**\*.wer'
       User   = 'AppData\Local\Microsoft\Windows\WER\**\*.wer' }
    # Windows Timeline (Windows 10; dropped in Windows 11).
    @{ Name = 'Windows Timeline'; Group = 3; User = 'AppData\Local\ConnectedDevicesPlatform\**\ActivitiesCache.db*' }
)

# ============================= FUNCTIONS =============================

# --- Filesystem enumeration (low-level first) ---

# True if Path is a junction or symbolic link. Links are never followed: on
# Windows they only duplicate real folders ("All Users", "Default User", the XP
# compatibility links such as "Local Settings" or "Application Data" inside
# profiles). Other reparse points (e.g. OneDrive cloud folders) are ordinary
# folders. Results are cached, as the same folders are checked for many patterns.
function Test-FolderLink {
    param([string]$Path)
    if ($script:linkCache.ContainsKey($Path)) { return $script:linkCache[$Path] }
    $isLink = $false
    try {
        $type   = (Get-Item -LiteralPath $Path -Force -ErrorAction Stop).LinkType
        $isLink = ($type -eq 'Junction' -or $type -eq 'SymbolicLink')
    } catch {}
    $script:linkCache[$Path] = $isLink
    return $isLink
}

# Full paths of the subfolders of Path matching Filter, skipping links (see
# Test-FolderLink).
function Get-ChildDirectory {
    param([string]$Path, [string]$Filter = '*')
    try {
        Get-ChildItem -LiteralPath $Path -Filter $Filter -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { $_.LinkType -ne 'Junction' -and $_.LinkType -ne 'SymbolicLink' } |
            ForEach-Object { $_.FullName }
    } catch {}
}

# A folder path safe to list: a bare drive ('C:') means that drive's current
# directory to PowerShell, so it becomes the drive root ('C:\').
function Get-ListPath {
    param([string]$Path)
    if ($Path -match '^[A-Za-z]:$') { return $Path + '\' }
    return $Path
}

# A folder and every folder below it, never following links (see Test-FolderLink).
function Get-DirectoryTree {
    param([string]$Path)
    $Path
    foreach ($d in (Get-ChildDirectory -Path (Get-ListPath -Path $Path))) { Get-DirectoryTree -Path $d }
}

# Expand a path pattern, relative to Root, into full file paths (none if absent).
# Segments are separated by '\'. The last segment is a file-name filter (wildcards
# allowed; a plain name matches just that file). A folder segment containing * or
# ? matches subfolders; '**' as the last folder segment means "anywhere below
# here" (recursive). Links are never followed (see Test-FolderLink). -Literal
# returns Root\Pattern unchecked, without listing it.
function Resolve-PathPattern {
    param([string]$Root, [string]$Pattern, [switch]$Literal)

    $base = $Root.TrimEnd('\')
    if ($Literal) { return ($base + '\' + $Pattern) }

    $segments = $Pattern -split '\\'
    $dirs     = @($base)
    $recurse  = $false
    foreach ($seg in ($segments | Select-Object -SkipLast 1)) {
        if     ($seg -eq '**')      { $recurse = $true }
        elseif ($seg -match '[*?]') { $dirs = @(foreach ($d in $dirs) { Get-ChildDirectory -Path (Get-ListPath -Path $d) -Filter $seg }) }
        else {
            $dirs = @(foreach ($d in $dirs) {
                $next = $d + '\' + $seg
                if (-not (Test-FolderLink -Path $next)) { $next }
            })
        }
    }
    if ($recurse) { $dirs = @(foreach ($d in $dirs) { Get-DirectoryTree -Path $d }) }
    foreach ($d in $dirs) {
        try {
            Get-ChildItem -LiteralPath (Get-ListPath -Path $d) -Filter $segments[-1] -File -Force -ErrorAction SilentlyContinue |
                ForEach-Object { $_.FullName }
        } catch {}
    }
}

# --- Registry ---

# A registry value with environment variables expanded, or $null if the key or
# value is absent or unreadable.
function Get-RegistryValue {
    param([string]$Path, [string]$Name)
    try {
        $value = (Get-ItemProperty -LiteralPath $Path -Name $Name -ErrorAction Stop).$Name
        if ($value) { [Environment]::ExpandEnvironmentVariables($value) }
    } catch {}
}

# User profiles: every folder under each profile root, in $profileRoots order
# (deliberately not the registry's ProfileList). A root that is itself a link
# (Documents and Settings -> Users on current Windows) is resolved to its target,
# and only if that stays on the system drive, so no profile is listed twice.
# Links inside a root ("All Users", "Default User") are skipped by
# Get-ChildDirectory. Service accounts are not profiles: rows list their paths.
function Get-UserProfilePath {
    $seen = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
    foreach ($r in $profileRoots) {
        try {
            $root = (Join-Path $sysDrive $r)
            $item = Get-Item -LiteralPath $root -Force -ErrorAction Stop
            if ($item.LinkType -eq 'Junction' -or $item.LinkType -eq 'SymbolicLink') {
                $root = @($item.Target)[0]
                if ($root -notlike "$sysDrive\*") { continue }
            }
            if ($seen.Add($root.TrimEnd('\'))) { Get-ChildDirectory -Path $root }
        } catch {}
    }
}

# Counting unit for CountBy 'Folder': the folder a match sits in at the pattern's
# own depth (its folder segments before any '**'), counted from Root. E.g. the
# browser profile folder for 'User Data\*\History*', or the History folder for
# 'History\**\index.dat', however deep the file itself is.
function Get-PatternUnit {
    param([string]$Root, [string]$Pattern, [string]$Path)
    $folders = @($Pattern -split '\\' | Select-Object -SkipLast 1)
    $depth   = [array]::IndexOf($folders, '**')
    if ($depth -lt 0) { $depth = $folders.Count }
    $base = $Root.TrimEnd('\')
    if ($depth -eq 0) { return $base }
    $parts = @($Path.Substring($base.Length + 1) -split '\\')
    return $base + '\' + (($parts | Select-Object -First $depth) -join '\')
}

# --- Zip ---

# True if an error (or any exception inside it) is "disk full" (ERROR_DISK_FULL,
# ERROR_HANDLE_DISK_FULL), i.e. the zip can't grow - as opposed to a locked file.
function Test-DiskFull {
    param($ErrorRecord)
    $e = $ErrorRecord.Exception
    while ($e) {
        if (($e.HResult -band 0xFFFF) -in 39, 112) { return $true }
        $e = $e.InnerException
    }
    return $false
}

# Copy one file straight into the zip, opening it with shared access so files
# held open by other processes (e.g. Edge History) can usually still be read.
# Returns $true (copied), $false (found but unreadable) or $null (already in zip).
# If the system drive fills up, sets $script:diskFull so collection stops.
function Add-FileToZip {
    param($Zip, [string]$Path)

    # C:\Users\bob\file.lnk -> C/Users/bob/file.lnk
    $entryName = ($Path -replace '^([A-Za-z]):', '$1') -replace '\\', '/'
    if (-not $script:added.Add($entryName)) { return $null }

    $src = $null
    $dst = $null
    # Paths of 260+ characters need the \\?\ prefix to open (where they could be listed).
    $openPath = if ($Path.Length -ge 260) { '\\?\' + $Path } else { $Path }
    try {
        $src = [System.IO.File]::Open($openPath, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
        $entry = $Zip.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Fastest)
        # UTC: zip stores a zone-less date/time, so keep it in the always-UTC convention.
        try { $entry.LastWriteTime = [System.IO.File]::GetLastWriteTimeUtc($openPath) } catch {}
        $dst = $entry.Open()
        $src.CopyTo($dst)
        $script:count++
        return $true
    } catch {
        if (Test-DiskFull -ErrorRecord $_) { $script:diskFull = $true }
        return $false   # locked / access denied (or disk full: see above)
    } finally {
        # Closing can fail too (e.g. disk full while flushing the entry): never let it escape.
        if ($dst) { try { $dst.Dispose() } catch {} }
        if ($src) { try { $src.Dispose() } catch {} }
    }
}

# --- Progress, collection, summary ---

# Rough progress: print "[n/total] Collecting <artefact>" as each artefact starts,
# so an operator sees movement on a slow/busy host. No counts - just a heartbeat.
function Write-Stage {
    param([string]$Name)
    $script:stageNum++
    Write-Output ("[{0:D2}/{1}] Collecting {2}" -f $script:stageNum, $script:stageTotal, $Name)
}

# Tally -> status string:
#   no candidates -> Missing; none read -> Not accessible; else "N collected[, M not accessible]"
function Format-Status {
    param([int]$Candidates, [int]$Collected, [int]$Failed)
    if     ($Candidates -eq 0) { 'Missing' }
    elseif ($Collected -eq 0)  { 'Not accessible' }
    elseif ($Failed -gt 0)     { "$Collected collected, $Failed not accessible" }
    else                       { "$Collected collected" }
}

# Collect one artefact row: resolve its patterns (system drive, then each user
# profile), stream every match into the zip as it is found, and set the row's one
# summary line. Each location is isolated: a failure skips only that location.
function Add-Artefact {
    param($Zip, [hashtable]$Artefact, [string[]]$UserProfile)

    Write-Stage -Name $Artefact.Name
    $tally = @{ Candidates = 0; Collected = 0; Failed = 0 }
    $units = @{}   # CountBy 'Folder': folder -> $true once any file in it was read

    $sources = @()
    foreach ($p in $Artefact.System) { $sources += @{ Root = $sysDrive; Scope = 'System'; Pattern = $p } }
    foreach ($rd in $Artefact.RegDirs) {
        $dir = Get-RegistryValue -Path $rd.Key -Name $rd.Value
        # Absolute local drive paths only (any letter): skips shares and relative paths.
        # Also skips the root of the system drive ($sysDrive, from %SystemDrive%), as a
        # recursive search would walk the whole drive; another drive's root is fine -
        # small partitions are sometimes set aside for transcripts.
        if ($dir -match '^[A-Za-z]:\\' -and $dir.TrimEnd('\') -ne $sysDrive) {
            $sources += @{ Root = $dir; Scope = 'System'; Pattern = $rd.Pattern }
        }
    }
    foreach ($u in $UserProfile) {
        foreach ($p in $Artefact.User) { $sources += @{ Root = $u; Scope = 'User'; Pattern = $p } }
    }

    :sources foreach ($s in $sources) {
        try {
            $patterns = @($s.Pattern)
            if ($Artefact.Logs) { $patterns += $s.Pattern + '.LOG*' }   # hive first, then its logs
            foreach ($pattern in $patterns) {
                foreach ($file in (Resolve-PathPattern -Root $s.Root -Pattern $pattern -Literal:([bool]$Artefact.Literal))) {
                    $ok = Add-FileToZip -Zip $Zip -Path $file
                    if ($script:diskFull) { $script:diskFullAt = $Artefact.Name; break sources }   # zip can't grow: stop
                    if ($null -eq $ok) { continue }   # already collected
                    if (-not $ok) {
                        $script:failed.Add([pscustomobject]@{
                            Path = $file; Scope = $s.Scope
                            Literal = [bool]$Artefact.Literal; GetFile = [bool]$Artefact.GetFile
                        })
                    }
                    if ($Artefact.CountBy -eq 'Folder') {
                        $unit = Get-PatternUnit -Root $s.Root -Pattern $pattern -Path $file
                        if (-not $units.ContainsKey($unit)) { $units[$unit] = @{ Main = $null; Any = $false } }
                        $leaf = Split-Path -Path $file -Leaf
                        if (@($Artefact.Supporting | Where-Object { $leaf -like $_ }).Count -gt 0) {
                            $units[$unit].Any = $units[$unit].Any -or $ok
                        } else {
                            $units[$unit].Main = ($units[$unit].Main -eq $true) -or $ok
                        }
                    } else {
                        $tally.Candidates++
                        if ($ok) { $tally.Collected++ } else { $tally.Failed++ }
                    }
                }
            }
        } catch {}
    }

    if ($Artefact.CountBy -eq 'Folder') {
        # Collected if the main file was read; supporting files only decide when a
        # unit has no main file at all (e.g. a lone journal).
        $tally.Candidates = $units.Count
        $tally.Collected  = @($units.Values | Where-Object { $_.Main -eq $true -or ($null -eq $_.Main -and $_.Any) }).Count
        $tally.Failed     = $tally.Candidates - $tally.Collected
    }
    $script:summary[$Artefact.Name] = Format-Status @tally
}

# --- Cleanup ---

# Queue the output folder for deletion at next boot: MoveFileEx with a null
# destination + MOVEFILE_DELAY_UNTIL_REBOOT (0x4) appends to the
# PendingFileRenameOperations registry value, processed in order at boot. Files go
# first (a folder is only removed once empty); files an earlier run already queued
# are skipped, so repeat runs don't pile up duplicates, while a file left behind
# by an earlier failed cleanup is picked up again. The folder itself goes last.
function Register-DeleteOnReboot {
    param([string]$Folder)
    try {
        if (-not ('LR.Native' -as [type])) {
            Add-Type -Namespace LR -Name Native -ErrorAction Stop -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet=System.Runtime.InteropServices.CharSet.Unicode, SetLastError=true)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
        }
        $pending = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
        try {
            $key = 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager'
            foreach ($entry in (Get-ItemProperty -LiteralPath $key -Name PendingFileRenameOperations -ErrorAction Stop).PendingFileRenameOperations) {
                if ($entry) { [void]$pending.Add($entry -replace '^\\\?\?\\', '') }
            }
        } catch {}
        # [NullString]::Value, not $null: PowerShell turns $null into "" for a
        # .NET string argument, and MoveFileEx only queues a delete for a true null.
        Get-ChildItem -LiteralPath $Folder -Recurse -Force -File -ErrorAction SilentlyContinue |
            Where-Object { -not $pending.Contains($_.FullName) } |
            ForEach-Object { [LR.Native]::MoveFileEx($_.FullName, [NullString]::Value, 4) | Out-Null }
        [LR.Native]::MoveFileEx($Folder, [NullString]::Value, 4) | Out-Null
    } catch {}
}

# =============================== MAIN ===============================

# Banner first, before any status, so the version is the first thing printed.
Write-Output "Live Response collector v$CollectorVersion"
Write-Output ("Host {0}, started {1}" -f $hostName, $runStart.ToString("yyyy-MM-dd'T'HH:mm:ss'Z'"))

# Script-scope state.
$script:added   = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$script:count   = 0                                                    # total files written to the zip
$script:failed  = New-Object 'System.Collections.Generic.List[object]' # found but unreadable: Path, Scope, Literal, GetFile
$script:linkCache = @{}                                                # folder path -> is a junction/symlink (Test-FolderLink)
$script:diskFull  = $false                                             # set when the system drive fills up (Test-DiskFull)
$script:diskFullAt = ''                                                # artefact being collected when it did
$script:summary = [ordered]@{}                                         # artefact name -> status, in display order

# Fix the run order once: group, then name ignoring non-alphanumerics. Collection,
# progress numbering and the summary all follow it. Lines start as 'Missing'.
$artefacts = @($artefacts | Sort-Object -Property { $_.Group }, { $_.Name -replace '[^A-Za-z0-9]', '' })
foreach ($a in $artefacts) { $script:summary[$a.Name] = 'Missing' }
$script:stageTotal = $artefacts.Count
$script:stageNum   = 0

$zip = $null
try {
    $dir = New-Item -ItemType Directory -Path $outDir -Force
    # Hidden + System keeps it out of a default Explorer view (and even when the
    # user has "show hidden files" on). IT, getfile, and -Force still see it fine.
    try { $dir.Attributes = $dir.Attributes -bor [System.IO.FileAttributes]::Hidden -bor [System.IO.FileAttributes]::System } catch {}
    Add-Type -AssemblyName System.IO.Compression
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zip = [System.IO.Compression.ZipFile]::Open($zipPath, [System.IO.Compression.ZipArchiveMode]::Create)
} catch {
    Write-Output "Could not create $zipPath"
    return
}

try {
    $userProfiles = @(Get-UserProfilePath)
    foreach ($a in $artefacts) {
        if ($script:diskFull) { break }
        try { Add-Artefact -Zip $zip -Artefact $a -UserProfile $userProfiles } catch {}
    }
} finally {
    if ($zip) { try { $zip.Dispose() } catch {} }   # writes the zip's index; can fail if the disk is full
}

# Disk full: the zip is partial (and its index may not have been written), so it
# is useless. Delete it, tell the analyst, and stop - they free space and re-run.
if ($script:diskFull) {
    try { Remove-Item -LiteralPath $zipPath -Force -ErrorAction Stop } catch {}
    Register-DeleteOnReboot -Folder $outDir
    Write-Output ''
    Write-Output "Collection stopped while collecting $($script:diskFullAt): $sysDrive is full."
    if (Test-Path -LiteralPath $zipPath) {
        Write-Output "The partial zip could not be deleted; it is unusable and queued for deletion at reboot."
    } else {
        Write-Output 'The partial zip was deleted.'
    }
    Write-Output "Free up space on $sysDrive and run the collector again."
    return
}

# Fallback cleanup: the output folder and its zips are deleted at the next reboot.
# getfile still works until then.
Register-DeleteOnReboot -Folder $outDir

# --- Output: summary, zip location, and runnable retrieval commands ---

Write-Output ''
Write-Output 'Artefact summary:'
# Name column sized to the longest artefact name, so the statuses line up.
$nameWidth = ($script:summary.Keys | ForEach-Object { $_.Length } | Measure-Object -Maximum).Maximum
foreach ($name in $script:summary.Keys) {
    Write-Output (("  {0,-" + $nameWidth + "} {1}") -f $name, $script:summary[$name])
}

$zipSize = ''
try {
    $bytes   = (Get-Item -LiteralPath $zipPath -Force).Length
    $mb      = [math]::Round($bytes / 1MB, 2)
    $zipSize = " ($mb MB)"
} catch {}

Write-Output ''
Write-Output "Collected $script:count files total$zipSize"
Write-Output "Retrieve with: getfile `"$zipPath`""

# Follow-up getfile commands for files this script found but couldn't read and
# the Defender sensor can retrieve directly - outcome-based: only reads that
# actually failed, in collection order (so metafiles first). Metafiles are listed
# only if flagged GetFile, with no Test-Path (PowerShell can't reliably see them);
# other files must still exist. Kept lean: machine-wide files only (no user-scope
# paths), and no transaction logs (an IR practitioner infers them from the hive).
$followups = New-Object 'System.Collections.Generic.List[string]'
foreach ($f in $script:failed) {
    if ($f.Literal) {
        if ($f.GetFile) { $followups.Add($f.Path) }
        continue
    }
    if ($f.Scope -eq 'User')            { continue }
    if ($f.Path -match '\.LOG\d*$')     { continue }
    if (Test-Path -LiteralPath $f.Path) { $followups.Add($f.Path) }
}
if ($followups.Count -gt 0) {
    # Bare commands under a title, so the block can be copied and pasted as-is.
    Write-Output ''
    Write-Output 'Additional inaccessible artefacts (locked from PowerShell - retrieve directly in this Live Response session):'
    foreach ($p in $followups) { Write-Output "getfile `"$p`"" }
}

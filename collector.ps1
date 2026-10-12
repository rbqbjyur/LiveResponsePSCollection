# SPDX-License-Identifier: 0BSD
#Requires -Version 5.1
<#
    Live Response collector.
    Upload to the Defender Live Response library, then:  run collector.ps1
    Retrieve the zip path printed at the end with:       getfile <path>

    Best effort: anything that can't be read is skipped silently.

    Version: $CollectorVersion below (semver). Changes are in CHANGELOG.md:
    https://github.com/rbqbjyur/LiveResponsePSCollection/blob/main/CHANGELOG.md
#>

# Every catch {} in this script is deliberate: failures are skipped and the run
# carries on (best effort, no failure log - see the project's design rules).
[Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSAvoidUsingEmptyCatchBlock', '',
    Justification = 'Best-effort collection: unreadable items are skipped silently by design.')]
param()

# ============================== CONFIG ==============================

$CollectorVersion = '0.16.0'

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# Resolve the system drive from the environment so the script is not tied to a C:
# install; every artefact path below is taken relative to it (or to a profile).
$sysDrive = $env:SystemDrive                 # e.g. C:

$hostName = $env:COMPUTERNAME
# UTC, so the name is unambiguous across time zones; trailing 'Z' marks it as UTC.
$runStart  = (Get-Date).ToUniversalTime()
$timestamp = $runStart.ToString('yyyyMMdd_HHmmss') + 'Z'

# Fixed, low-profile folder that holds the output of every run. Each run drops a
# separately-named zip in here, so repeated collections accumulate side by side.
$outDir  = Join-Path $sysDrive 'LiveResponse'
$zipPath = Join-Path $outDir "${hostName}_${timestamp}.zip"

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
#   RegDirs  Folders named by registry values (Key, Value), each searched with its
#            Pattern. Local drive paths only: shares are skipped (no network access).
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
    # Program Compatibility Assistant execution records (Windows 11 22H2+).
    @{ Name = 'AppCompat PCA'; Group = 2; System = 'Windows\appcompat\pca\*' }
    # BITS job database (qmgr.db) and its ESE logs: downloads and persistence.
    @{ Name = 'BITS';          Group = 2; System = 'ProgramData\Microsoft\Network\Downloader\**\*' }
    # Defender text logs (MPLog etc.) and detection history; not the quarantine
    # (payload). Defender event logs are already covered by EVTX.
    @{ Name = 'Defender Logs'; Group = 2; System = @(
        'ProgramData\Microsoft\Windows Defender\Support\**\*'
        'ProgramData\Microsoft\Windows Defender\Scans\History\Service\DetectionHistory\**\*'
        'ProgramData\Microsoft\Windows Defender\Scans\History\Service\Detections.log'
        'Windows\Temp\MpCmdRun.log'
    ) }
    @{ Name = 'EVTX';          Group = 2; System = 'Windows\System32\winevt\logs\*.evtx' }
    @{ Name = 'Firewall Log';  Group = 2; System = 'Windows\System32\LogFiles\Firewall\pfirewall.*' }   # logging off by default
    @{ Name = 'Prefetch';      Group = 2; System = 'Windows\Prefetch\*.pf' }
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
        'Windows\AppCompat\Programs\Amcache.hve'
    ) }
    # XML task definitions, plus PowerShell scheduled jobs (definitions and output).
    @{ Name = 'Scheduled Tasks'; Group = 2
       System = @(
           'Windows\System32\Tasks\**\*'
           'Windows\SysWOW64\Tasks\**\*'
           'Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\**\*'
           'Windows\SysWOW64\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\**\*'
       )
       User = 'AppData\Local\Microsoft\Windows\PowerShell\ScheduledJobs\**\*' }
    @{ Name = 'SetupAPI'; Group = 2; System = 'Windows\INF\setupapi*.log' }   # not legacy <windir>\setupapi.log
    # SRUDB.dat plus its ESE logs and checkpoint, for dirty-database recovery.
    @{ Name = 'SRUM';     Group = 2; System = 'Windows\System32\SRU\**\*' }

    # 3. User-specific. Service accounts (SYSTEM, LocalService, NetworkService) are
    # not user profiles; where they matter, their paths are listed under System.
    # .NET CLR usage logs: one log per process that loaded the CLR (e.g. .NET tooling).
    @{ Name = '.NET CLR Usage Logs'; Group = 3
       System = 'Windows\System32\config\systemprofile\AppData\Local\Microsoft\CLR_*\**\*.log'
       User   = 'AppData\Local\Microsoft\CLR_*\**\*.log' }
    # Browser history: maintained browsers, one pattern per browser (or channel),
    # counted per user x browser x profile. History DB only (plus its journal).
    @{ Name = 'Browser History'; Group = 3; CountBy = 'Folder'
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
       ) }
    # File History: metadata about backed-up files (only present when enabled).
    @{ Name = 'File History'; Group = 3; User = 'AppData\Local\Microsoft\Windows\FileHistory\Configuration\Catalog*.edb' }
    @{ Name = 'JumpLists';    Group = 3; User = @(
        'AppData\Roaming\Microsoft\Windows\Recent\AutomaticDestinations\*.automaticDestinations-ms'
        'AppData\Roaming\Microsoft\Windows\Recent\CustomDestinations\*.customDestinations-ms'
    ) }
    # Shortcuts: recent files, Office recent, desktop and Start Menu (top level only).
    @{ Name = 'LNK'; Group = 3
       System = 'ProgramData\Microsoft\Windows\Start Menu\Programs\*.lnk'
       User = @(
           'AppData\Roaming\Microsoft\Windows\Recent\*.lnk'
           'AppData\Roaming\Microsoft\Office\Recent\**\*'
           'Desktop\*.lnk'
           'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\*.lnk'
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
    @{ Name = 'Recycle Bin ($I)'; Group = 3; System = '$Recycle.Bin\*\$I*' }   # $I metadata only, no $R content
    # User hives, plus the service accounts' hives: DEFAULT is the SYSTEM account's
    # (HKU\.DEFAULT / S-1-5-18), the others LocalService and NetworkService.
    @{ Name = 'Registry Hives (user)'; Group = 3; Logs = $true
       System = @(
           'Windows\System32\config\DEFAULT'
           'Windows\System32\config\systemprofile\NTUSER.DAT'
           'Windows\ServiceProfiles\LocalService\NTUSER.DAT'
           'Windows\ServiceProfiles\NetworkService\NTUSER.DAT'
       )
       User = @(
           'NTUSER.DAT'
           'AppData\Local\Microsoft\Windows\UsrClass.dat'
       ) }
    @{ Name = 'Startup Folders'; Group = 3
       System = 'ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\**\*'
       User   = 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\**\*' }
    # WER: only the .wer report metadata, never the crash dumps (binary payload).
    @{ Name = 'WER'; Group = 3
       System = 'ProgramData\Microsoft\Windows\WER\**\*.wer'
       User   = 'AppData\Local\Microsoft\Windows\WER\**\*.wer' }
)

# ============================= FUNCTIONS =============================

# --- Filesystem enumeration (low-level first) ---

# Full paths of the subfolders of Path matching Filter, skipping reparse points
# (junctions such as "All Users" / "Default User" only duplicate real folders).
function Get-ChildDirectory {
    param([string]$Path, [string]$Filter = '*')
    try {
        Get-ChildItem -LiteralPath $Path -Filter $Filter -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { -not ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) } |
            ForEach-Object { $_.FullName }
    } catch {}
}

# Expand a path pattern, relative to Root, into full file paths (none if absent).
# Segments are separated by '\'. The last segment is a file-name filter (wildcards
# allowed; a plain name matches just that file). A folder segment containing * or
# ? matches subfolders; '**' as the last folder segment means "anywhere below
# here" (recursive). -Literal returns Root\Pattern unchecked, without listing it.
function Resolve-PathPattern {
    param([string]$Root, [string]$Pattern, [switch]$Literal)

    $base = $Root.TrimEnd('\')
    if ($Literal) { return ($base + '\' + $Pattern) }

    $segments = $Pattern -split '\\'
    $dirs     = @($base)
    $recurse  = $false
    foreach ($seg in ($segments | Select-Object -SkipLast 1)) {
        if     ($seg -eq '**')      { $recurse = $true }
        elseif ($seg -match '[*?]') { $dirs = @(foreach ($d in $dirs) { Get-ChildDirectory -Path $d -Filter $seg }) }
        else                        { $dirs = @(foreach ($d in $dirs) { $d + '\' + $seg }) }
    }
    foreach ($d in $dirs) {
        try {
            Get-ChildItem -LiteralPath $d -Filter $segments[-1] -File -Force -Recurse:$recurse -ErrorAction SilentlyContinue |
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

# User profiles: every folder under <sysDrive>\Users (deliberately not the
# registry's ProfileList). Junctions there ("All Users", "Default User") are
# skipped: they only lead back to folders already covered. Service accounts are
# not profiles: rows list their paths explicitly.
function Get-UserProfilePath {
    Get-ChildDirectory -Path (Join-Path $sysDrive 'Users')
}

# --- Zip ---

# Copy one file straight into the zip, opening it with shared access so files
# held open by other processes (e.g. Edge History) can usually still be read.
# Returns $true (copied), $false (found but unreadable) or $null (already in zip).
function Add-FileToZip {
    param($Zip, [string]$Path)

    # C:\Users\bob\file.lnk -> C/Users/bob/file.lnk
    $entryName = ($Path -replace '^([A-Za-z]):', '$1') -replace '\\', '/'
    if (-not $script:added.Add($entryName)) { return $null }

    $src = $null
    $dst = $null
    try {
        $src = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
        $entry = $Zip.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Fastest)
        # UTC: zip stores a zone-less date/time, so keep it in the always-UTC convention.
        try { $entry.LastWriteTime = [System.IO.File]::GetLastWriteTimeUtc($Path) } catch {}
        $dst = $entry.Open()
        $src.CopyTo($dst)
        $script:count++
        return $true
    } catch {
        return $false   # locked / access denied
    } finally {
        if ($dst) { $dst.Dispose() }
        if ($src) { $src.Dispose() }
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
        # Local drive paths only (e.g. D:\Transcripts): skips shares and relative paths.
        if ($dir -match '^[A-Za-z]:\\') { $sources += @{ Root = $dir; Scope = 'System'; Pattern = $rd.Pattern } }
    }
    foreach ($u in $UserProfile) {
        foreach ($p in $Artefact.User) { $sources += @{ Root = $u; Scope = 'User'; Pattern = $p } }
    }

    foreach ($s in $sources) {
        try {
            $patterns = @($s.Pattern)
            if ($Artefact.Logs) { $patterns += $s.Pattern + '.LOG*' }   # hive first, then its logs
            foreach ($pattern in $patterns) {
                foreach ($file in (Resolve-PathPattern -Root $s.Root -Pattern $pattern -Literal:([bool]$Artefact.Literal))) {
                    $ok = Add-FileToZip -Zip $Zip -Path $file
                    if ($null -eq $ok) { continue }   # already collected
                    if (-not $ok) {
                        $script:failed.Add([pscustomobject]@{
                            Path = $file; Scope = $s.Scope
                            Literal = [bool]$Artefact.Literal; GetFile = [bool]$Artefact.GetFile
                        })
                    }
                    if ($Artefact.CountBy -eq 'Folder') {
                        $folder = Split-Path -Path $file -Parent
                        $units[$folder] = [bool]$units[$folder] -or $ok
                    } else {
                        $tally.Candidates++
                        if ($ok) { $tally.Collected++ } else { $tally.Failed++ }
                    }
                }
            }
        } catch {}
    }

    if ($Artefact.CountBy -eq 'Folder') {
        $tally.Candidates = $units.Count
        $tally.Collected  = @($units.Values | Where-Object { $_ }).Count
        $tally.Failed     = $tally.Candidates - $tally.Collected
    }
    $script:summary[$Artefact.Name] = Format-Status @tally
}

# --- Cleanup ---

# MoveFileEx with a null destination + MOVEFILE_DELAY_UNTIL_REBOOT (0x4) queues a
# path for deletion on next boot via the PendingFileRenameOperations registry key.
function Register-DeleteOnReboot {
    param([string]$Path)
    try {
        if (-not ('LR.Native' -as [type])) {
            Add-Type -Namespace LR -Name Native -ErrorAction Stop -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet=System.Runtime.InteropServices.CharSet.Unicode, SetLastError=true)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@
        }
        # Files first, then directories deepest-first, then the root: the queue is
        # processed in order, and a directory is only removed once it is empty.
        # [NullString]::Value, not $null: PowerShell turns $null into "" for a
        # .NET string argument, and MoveFileEx only queues a delete for a true null.
        Get-ChildItem -LiteralPath $Path -Recurse -Force -File -ErrorAction SilentlyContinue |
            ForEach-Object { [LR.Native]::MoveFileEx($_.FullName, [NullString]::Value, 4) | Out-Null }
        Get-ChildItem -LiteralPath $Path -Recurse -Force -Directory -ErrorAction SilentlyContinue |
            Sort-Object -Property { $_.FullName.Length } -Descending |
            ForEach-Object { [LR.Native]::MoveFileEx($_.FullName, [NullString]::Value, 4) | Out-Null }
        [LR.Native]::MoveFileEx($Path, [NullString]::Value, 4) | Out-Null
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
        try { Add-Artefact -Zip $zip -Artefact $a -UserProfile $userProfiles } catch {}
    }
} finally {
    if ($zip) { $zip.Dispose() }
}

# Fallback cleanup: if the folder is never removed manually, it (and everything
# in it) is deleted at the next reboot. getfile still works until then.
Register-DeleteOnReboot -Path $outDir

# --- Output: summary, zip location, and runnable retrieval commands ---

Write-Output ''
Write-Output 'Artefact summary:'
foreach ($name in $script:summary.Keys) {
    Write-Output ("  {0,-24} {1}" -f $name, $script:summary[$name])
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

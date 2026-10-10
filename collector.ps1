# SPDX-License-Identifier: 0BSD
#Requires -Version 5.1
<#
    Live Response collector.
    Upload to the Defender Live Response library, then:  run collector.ps1
    Retrieve the zip path printed at the end with:       getfile <path>

    Best effort: anything that can't be read is skipped silently.

    Changelog (pre-1.0.0; assigned retroactively). Minor (0.x.0) = new artefact
    or behaviour change; patch (0.0.x) = rename / vanity / output-only tweak.
      0.1.0 - Initial collector: Recycle Bin $I, LNK, JumpLists, Edge History.
      0.2.0 - Consolidated output into a single fixed, hidden (Hidden+System)
              folder instead of a per-run folder.
      0.3.0 - Zip compression set to Fastest (still streamed into the zip).
      0.4.0 - Delete-on-reboot fallback cleanup for the output folder
              (folder also renamed to C:\LiveResponse).
      0.5.0 - Added EVTX, Prefetch, SRUM, PowerShell history + transcripts.
      0.5.1 - Per-artefact status summary printed at end of run (output only).
      0.6.0 - Added system + user registry hives (SAM/SOFTWARE/SYSTEM/Amcache,
              NTUSER.DAT/UsrClass.dat); also report final zip size.
      0.7.0 - Handle NTFS metafiles $MFT and $UsnJrnl:$J. PowerShell cannot read
              these; they appear in the summary as placeholders ('Not accessible')
              and the run prints the getfile command for the ones the sensor can
              retrieve ($MFT). $UsnJrnl:$J is not getfile-retrievable; noted only.
      0.8.0 - Added Chrome and Firefox history. Browser history is table-driven
              ($browsers) and reported as one 'Browser History' summary line that
              counts histories (user x browser x browser-profile), not files.
      0.8.1 - Summary order fixed up front in three groups (C:\ root, system,
              user), alphabetical within each ignoring non-alphanumerics. Files
              are streamed into the zip as found (single pass); each artefact's
              one summary line is tallied across calls and finalised at the end.
      0.8.2 - End of run now prints only runnable commands after the zip's Retrieve
              line (getfile for $MFT). Metafiles with no getfile route ($UsnJrnl:$J)
              are shown in the summary only, not as an end note.
      0.9.0 - Added SECURITY hive (into system hives), Scheduled Tasks (recursive),
              Startup folders (machine + per-user), WER report metadata (.wer only,
              no crash dumps), and the $LogFile metafile (getfile, like $MFT).
      0.10.0 - Added SetupAPI device-install logs (INF\setupapi*.log) and the
               Windows Firewall log (pfirewall*.log, best effort).
      0.11.0 - Added File History catalogs (per-user Catalog*.edb metadata about
               backed-up files; present only when File History is enabled).
      0.12.0 - Collect registry transaction logs (.LOG1/.LOG2) alongside every
               system and user hive, for dirty-hive replay / recent-change recovery.
      0.12.1 - Print a rough per-artefact progress line "[n/total] Collecting <x>"
               (first touch, no numbers) as a heartbeat on slow hosts.
      0.12.2 - Structural tidy only (no behaviour change): CONFIG/FUNCTIONS/MAIN
               sections, helpers ordered low-level first, added #Requires 5.1.
      0.13.0 - Resolve system paths from %SystemDrive%/%SystemRoot%/%ProgramData%
               (works on non-C: installs); UTC zip-name timestamp (trailing 'Z');
               renamed Collect->Add-Artefact and Announce->Write-Stage (approved verbs).
      0.13.1 - Anchor all paths to $sysDrive only (dropped $sysRoot/$progData);
               Windows\ and ProgramData\ are taken relative to the system drive.
      0.13.2 - End of run prints getfile follow-ups for 'Not accessible' files that
               still exist and getfile supports (locked hives/SRUM/metafiles),
               excluding transaction logs and anything under \Users for brevity;
               zip size moved onto the "Collected" line (no Output line); follow-ups
               listed as bare commands under an "Additional inaccessible artefacts"
               title (clarifying they need the Live Response session) for copy-paste.
      0.13.3 - User profiles are just the folders under \Users (dropped the
               ProfileList enumeration); excludes the service/system accounts
               (LocalService/NetworkService/systemprofile) under \Windows - low
               value and broader than KAPE.
      0.13.4 - Metafile getfile follow-ups ($MFT/$LogFile) are now outcome-based:
               printed only if the read actually failed, not unconditionally.
      0.13.5 - Fix delete-on-reboot cleanup: pass a true null destination to
               MoveFileEx ([NullString]::Value; $null was passed as "", so the
               output folder was never deleted on reboot - confirmed in testing).
               Added SPDX identifier (0BSD).
#>

# ============================== CONFIG ==============================

$CollectorVersion = '0.13.5'

$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference    = 'SilentlyContinue'

# Resolve the system drive from the environment so the script is not tied to a C:
# install; the Windows and ProgramData folders are taken relative to it.
$sysDrive = $env:SystemDrive                 # e.g. C:

$hostName  = $env:COMPUTERNAME
# UTC, so the name is unambiguous across time zones; trailing 'Z' marks it as UTC.
$timestamp = (Get-Date).ToUniversalTime().ToString('yyyyMMdd_HHmmss') + 'Z'

# Fixed, low-profile folder that holds the output of every run. Each run drops a
# separately-named zip in here, so repeated collections accumulate side by side.
$outDir  = Join-Path $sysDrive 'LiveResponse'
$zipPath = Join-Path $outDir "${hostName}_${timestamp}.zip"

# NTFS metafiles. PowerShell cannot open these, so they are kept only as summary
# placeholders (always 'Not accessible') - retained so future raw/sensor-based
# collection slots in cleanly. 'GetFile' marks the ones the Defender sensor's
# getfile can retrieve directly ($MFT and $LogFile work; $UsnJrnl:$J does not).
# These are the timeline-relevant NTFS metafiles (the "NTFS Triforce").
$metaFiles = @(
    @{ Name = '$LogFile';    Path = ($sysDrive + '\$LogFile');            GetFile = $true  }
    @{ Name = '$MFT';        Path = ($sysDrive + '\$MFT');                GetFile = $true  }
    @{ Name = '$UsnJrnl:$J'; Path = ($sysDrive + '\$Extend\$UsnJrnl:$J'); GetFile = $false }
)

# Browser history sources. Each has a base dir (relative to a user profile) that
# contains one or more browser-profile subdirs, each holding history files that
# match Filter. Add a row here to cover another browser. Counted as one "history"
# per user x browser x browser-profile that has a match (see Browser History).
$browsers = @(
    @{ Name = 'Edge';    Base = 'AppData\Local\Microsoft\Edge\User Data';   Filter = 'History*' }
    @{ Name = 'Chrome';  Base = 'AppData\Local\Google\Chrome\User Data';    Filter = 'History*' }
    @{ Name = 'Firefox'; Base = 'AppData\Roaming\Mozilla\Firefox\Profiles'; Filter = 'places.sqlite*' }
)

# End-of-run summary. The display order is fixed here, once, in three groups
# (C:\ root, system, user) sorted alphabetically within each ignoring the
# non-alphanumeric prefix - so a line's position never depends on when its result
# is recorded. Values start at 'Missing' and are filled in as collection runs.
$script:summary = [ordered]@{}
foreach ($n in '$LogFile', '$MFT', '$UsnJrnl:$J',
               'EVTX', 'Firewall Log', 'Prefetch', 'Registry Hives (system)', 'Scheduled Tasks', 'SetupAPI', 'SRUM',
               'Browser History', 'File History', 'JumpLists', 'LNK', 'PowerShell History',
               'PowerShell Transcripts', 'Recycle Bin ($I)', 'Registry Hives (user)',
               'Startup Folders', 'WER') {
    $script:summary[$n] = 'Missing'
}

# Script-scope state.
$script:added      = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)
$script:tally      = @{}                      # per-artefact running counts
$script:count      = 0                        # total files written to the zip
$script:failed     = New-Object 'System.Collections.Generic.List[string]'  # paths that existed but could not be read
$script:stageTotal = $script:summary.Count    # progress denominator
$script:stageNum   = 0
$script:announced  = New-Object 'System.Collections.Generic.HashSet[string]' ([StringComparer]::OrdinalIgnoreCase)

# MoveFileEx with a null destination + MOVEFILE_DELAY_UNTIL_REBOOT (0x4) queues a
# path for deletion on next boot via the PendingFileRenameOperations registry key.
try {
    Add-Type -Namespace LR -Name Native -MemberDefinition @'
[System.Runtime.InteropServices.DllImport("kernel32.dll", CharSet=System.Runtime.InteropServices.CharSet.Unicode, SetLastError=true)]
public static extern bool MoveFileEx(string lpExistingFileName, string lpNewFileName, int dwFlags);
'@ -ErrorAction SilentlyContinue
} catch {}

# ============================= FUNCTIONS =============================

# --- Filesystem enumeration (low-level first) ---

function Get-Files {
    param([string]$Dir, [string]$Filter)
    try { Get-ChildItem -LiteralPath $Dir -Filter $Filter -File -Force -ErrorAction SilentlyContinue } catch {}
}

function Get-Dirs {
    param([string]$Dir)
    try {
        Get-ChildItem -LiteralPath $Dir -Directory -Force -ErrorAction SilentlyContinue |
            Where-Object { -not ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) }
    } catch {}
}

# Full paths of files matching a glob in a directory (empty if the dir is absent).
function Find-Files {
    param([string]$Dir, [string]$Filter)
    @(Get-Files $Dir $Filter | ForEach-Object { $_.FullName })
}

# Full paths of files under a directory tree, optionally filtered (empty if absent).
function Find-FilesRecurse {
    param([string]$Dir, [string]$Filter = '*')
    try { @(Get-ChildItem -LiteralPath $Dir -Recurse -Filter $Filter -File -Force -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName }) } catch {}
}

# User profiles: the folders under <sysDrive>\Users. Get-Dirs skips the junction
# pseudo-folders ("All Users", "Default User"); service/system accounts live under
# \Windows and so are intentionally excluded.
function Get-UserProfiles {
    Get-Dirs (Join-Path $sysDrive 'Users') | ForEach-Object { $_.FullName }
}

# --- Zip ---

# Copy one file straight into the zip, opening it with shared access so files
# held open by other processes (e.g. Edge History) can usually still be read.
function Add-FileToZip {
    param($Zip, [string]$Path)

    # C:\Users\bob\file.lnk -> C/Users/bob/file.lnk
    $entryName = ($Path -replace '^([A-Za-z]):', '$1') -replace '\\', '/'
    if (-not $script:added.Add($entryName)) { return $null }  # already collected

    $src = $null
    $dst = $null
    try {
        $src = [System.IO.File]::Open($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]'ReadWrite, Delete')
        $entry = $Zip.CreateEntry($entryName, [System.IO.Compression.CompressionLevel]::Fastest)
        try { $entry.LastWriteTime = [System.IO.File]::GetLastWriteTime($Path) } catch {}
        $dst = $entry.Open()
        $src.CopyTo($dst)
        $script:count++
        return $true
    } catch {
        $script:failed.Add($Path)   # found but could not be read (locked / access denied)
        return $false
    } finally {
        if ($dst) { $dst.Dispose() }
        if ($src) { $src.Dispose() }
    }
}

# --- Progress, collection, summary ---

# Rough progress: print "[n/total] Collecting <artefact>" once per artefact, the
# first time it is collected, so an operator sees movement on a slow/busy host.
# Total is the number of summary lines; collection order below is deterministic,
# so the numbering is stable. No counts/percentages - just a heartbeat.
function Write-Stage {
    param([string]$Name)
    if ($script:announced.Add($Name)) {
        $script:stageNum++
        Write-Output ("[{0:D2}/{1}] Collecting {2}" -f $script:stageNum, $script:stageTotal, $Name)
    }
}

# Stream a set of files for one artefact into the zip the moment they are found
# (no second pass), accumulating one summary tally across calls.
function Add-Artefact {
    param($Zip, [string]$Name, $Files)
    Write-Stage $Name
    $t = $script:tally[$Name]
    if (-not $t) { $t = @{ Candidates = 0; Collected = 0; Failed = 0 }; $script:tally[$Name] = $t }
    foreach ($p in $Files) {
        $t.Candidates++
        $r = Add-FileToZip $Zip $p
        if     ($r -eq $true)  { $t.Collected++ }
        elseif ($r -eq $false) { $t.Failed++ }
    }
}

# Tally (or raw counts) -> status string, shared by file artefacts and browsers.
#   no candidates -> Missing; none read -> Not accessible; else "N collected[, M not accessible]"
function Format-Status {
    param($Candidates, $Collected, $Failed)
    if     ($Candidates -eq 0) { 'Missing' }
    elseif ($Collected -eq 0)  { 'Not accessible' }
    elseif ($Failed -gt 0)     { "$Collected collected, $Failed not accessible" }
    else                       { "$Collected collected" }
}

# --- Cleanup ---

function Register-DeleteOnReboot {
    param([string]$Root)
    try {
        # Files first, then directories deepest-first, then the root: the queue is
        # processed in order, and a directory is only removed once it is empty.
        # [NullString]::Value, not $null: PowerShell turns $null into "" for a
        # .NET string argument, and MoveFileEx only queues a delete for a true null.
        Get-ChildItem -LiteralPath $Root -Recurse -Force -File -ErrorAction SilentlyContinue |
            ForEach-Object { [LR.Native]::MoveFileEx($_.FullName, [NullString]::Value, 4) | Out-Null }
        Get-ChildItem -LiteralPath $Root -Recurse -Force -Directory -ErrorAction SilentlyContinue |
            Sort-Object { $_.FullName.Length } -Descending |
            ForEach-Object { [LR.Native]::MoveFileEx($_.FullName, [NullString]::Value, 4) | Out-Null }
        [LR.Native]::MoveFileEx($Root, [NullString]::Value, 4) | Out-Null
    } catch {}
}

# =============================== MAIN ===============================

# Banner first, before any status, so the version is the first thing printed.
Write-Output "Live Response collector v$CollectorVersion"

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
    # Files are added to the zip the moment they are found (one pass). Summary
    # ORDER is fixed by the seeding above; the order of collection below is chosen
    # only for efficiency, and does not affect how the summary reads.

    # NTFS metafiles (C:\ root): placeholders - PowerShell can't open them, so they
    # always report 'Not accessible'; retrieval via getfile is printed at the end.
    foreach ($m in $metaFiles) { Add-Artefact $zip $m.Name @($m.Path) }

    # System files
    Add-Artefact $zip 'EVTX'     (Find-Files (Join-Path $sysDrive 'Windows\System32\winevt\logs') '*')
    Add-Artefact $zip 'Prefetch' (Find-Files (Join-Path $sysDrive 'Windows\Prefetch') '*.pf')
    # Device/driver install history (modern INF logs, not the legacy <windir>\setupapi.log)
    Add-Artefact $zip 'SetupAPI' (Find-Files (Join-Path $sysDrive 'Windows\INF') 'setupapi*.log')
    # Windows Firewall log (usually off by default, so often absent - best effort)
    Add-Artefact $zip 'Firewall Log' (Find-Files (Join-Path $sysDrive 'Windows\System32\LogFiles\Firewall') 'pfirewall*.log')
    $srumPath = Join-Path $sysDrive 'Windows\System32\SRU\SRUDB.dat'
    $srum = @(); if (Test-Path -LiteralPath $srumPath) { $srum = @($srumPath) }
    Add-Artefact $zip 'SRUM' $srum
    # Hives plus their transaction logs (.LOG1/.LOG2) - the logs hold un-flushed
    # changes, so EZ Registry Explorer / RegRipper / plaso can replay a dirty hive
    # and recover the most recent entries (better timeline completeness).
    foreach ($h in (Join-Path $sysDrive 'Windows\System32\config\SAM'),
                   (Join-Path $sysDrive 'Windows\System32\config\SECURITY'),
                   (Join-Path $sysDrive 'Windows\System32\config\SOFTWARE'),
                   (Join-Path $sysDrive 'Windows\System32\config\SYSTEM'),
                   (Join-Path $sysDrive 'Windows\AppCompat\Programs\Amcache.hve')) {
        if (Test-Path -LiteralPath $h) { Add-Artefact $zip 'Registry Hives (system)' @($h) }
        Add-Artefact $zip 'Registry Hives (system)' (Find-Files (Split-Path $h -Parent) ((Split-Path $h -Leaf) + '.LOG*'))
    }

    # Scheduled tasks (XML task definitions, recursive)
    Add-Artefact $zip 'Scheduled Tasks' (Find-FilesRecurse (Join-Path $sysDrive 'Windows\System32\Tasks'))

    # Recycle Bin metadata ($I) only, no $R content
    foreach ($sidDir in Get-Dirs ($sysDrive + '\$Recycle.Bin')) { Add-Artefact $zip 'Recycle Bin ($I)' (Find-Files $sidDir.FullName '$I*') }

    # Startup folders and WER - machine-wide locations (per-user handled in the loop).
    # WER: only the .wer report metadata, never the crash dumps (binary payload).
    Add-Artefact $zip 'Startup Folders' (Find-FilesRecurse (Join-Path $sysDrive 'ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp'))
    Add-Artefact $zip 'WER'             (Find-FilesRecurse (Join-Path $sysDrive 'ProgramData\Microsoft\Windows\WER') '*.wer')

    # Per-profile user artefacts. Browser history is counted per unit (user x
    # browser x browser-profile), not per file, so it is tallied separately here.
    $bFound = 0; $bOk = 0; $bFail = 0
    foreach ($userProfile in Get-UserProfiles) {
        $recent = Join-Path $userProfile 'AppData\Roaming\Microsoft\Windows\Recent'
        Add-Artefact $zip 'LNK'       (Find-Files $recent '*.lnk')
        Add-Artefact $zip 'JumpLists' (Find-Files (Join-Path $recent 'AutomaticDestinations') '*.automaticDestinations-ms')

        # User registry hives + their transaction logs (.LOG1/.LOG2, as above)
        foreach ($h in (Join-Path $userProfile 'NTUSER.DAT'),
                       (Join-Path $userProfile 'AppData\Local\Microsoft\Windows\UsrClass.dat')) {
            if (Test-Path -LiteralPath $h) { Add-Artefact $zip 'Registry Hives (user)' @($h) }
            Add-Artefact $zip 'Registry Hives (user)' (Find-Files (Split-Path $h -Parent) ((Split-Path $h -Leaf) + '.LOG*'))
        }

        # File History catalogs - metadata about backed-up files (names, paths, times), not the files
        Add-Artefact $zip 'File History' (Find-Files (Join-Path $userProfile 'AppData\Local\Microsoft\Windows\FileHistory\Configuration') 'Catalog*.edb')

        # Browser history: one unit per browser-profile that has a match
        Write-Stage 'Browser History'
        foreach ($b in $browsers) {
            foreach ($bProfile in Get-Dirs (Join-Path $userProfile $b.Base)) {
                $bFiles = Find-Files $bProfile.FullName $b.Filter
                if ($bFiles.Count -eq 0) { continue }
                $bFound++
                $read = $false
                foreach ($f in $bFiles) { if ((Add-FileToZip $zip $f) -eq $true) { $read = $true } }
                if ($read) { $bOk++ } else { $bFail++ }
            }
        }

        $hist = Join-Path $userProfile 'AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt'
        $phist = @(); if (Test-Path -LiteralPath $hist) { $phist = @($hist) }
        Add-Artefact $zip 'PowerShell History' $phist

        # PowerShell transcripts (default location is the user's Documents folder)
        Add-Artefact $zip 'PowerShell Transcripts' (Find-Files (Join-Path $userProfile 'Documents') 'PowerShell_transcript.*.txt')

        # Startup folder (persistence) and WER report metadata (.wer only, no dumps)
        Add-Artefact $zip 'Startup Folders' (Find-FilesRecurse (Join-Path $userProfile 'AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup'))
        Add-Artefact $zip 'WER'             (Find-FilesRecurse (Join-Path $userProfile 'AppData\Local\Microsoft\Windows\WER') '*.wer')
    }

    # Finalise one summary line per artefact from its tally (browser from its units).
    foreach ($name in @($script:tally.Keys)) {
        $t = $script:tally[$name]
        $script:summary[$name] = Format-Status $t.Candidates $t.Collected $t.Failed
    }
    $script:summary['Browser History'] = Format-Status $bFound $bOk $bFail
} catch {
} finally {
    if ($zip) { $zip.Dispose() }
}

# Fallback cleanup: if the folder is never removed manually, it (and everything
# in it) is deleted at the next reboot. getfile still works until then.
Register-DeleteOnReboot $outDir

# --- Output: summary, zip location, and runnable retrieval commands ---

Write-Output ''
Write-Output 'Artefact summary:'
foreach ($name in $script:summary.Keys) {
    Write-Output ("  {0,-24} {1}" -f $name, $script:summary[$name])
}

$zipSize = ''
try {
    $bytes = (Get-Item -LiteralPath $zipPath -Force).Length
    $mb    = [math]::Round($bytes / 1MB, 2)
    $zipSize = " ($mb MB)"
} catch {}

Write-Output ''
Write-Output "Collected $script:count files total$zipSize"
Write-Output "Retrieve with: getfile `"$zipPath`""

# Follow-up getfile commands for things this script couldn't read but the Defender
# sensor can retrieve directly - outcome-based: only files that actually came back
# 'Not accessible' (locked/denied). NTFS metafiles are listed first, and only if
# flagged getfile-capable (not $UsnJrnl:$J); no Test-Path for them, as PowerShell
# can't reliably see metafiles. Other files must still exist on disk. Kept lean:
# skip transaction logs (an IR practitioner infers them from the primary hive)
# and anything under \Users (only machine-wide items here).
$metaPaths = @($metaFiles | ForEach-Object { $_.Path })
$usersRoot = Join-Path $sysDrive 'Users'
$followups = New-Object 'System.Collections.Generic.List[string]'
foreach ($m in $metaFiles) { if ($m.GetFile -and $script:failed.Contains($m.Path)) { $followups.Add($m.Path) } }
foreach ($p in ($script:failed | Sort-Object -Unique)) {
    if ($metaPaths -contains $p)   { continue }   # metafiles handled above
    if ($p -like "$usersRoot\*")   { continue }   # skip user files for simplicity
    if ($p -match '\.LOG\d*$')     { continue }   # skip transaction logs (imply from the hive)
    if (Test-Path -LiteralPath $p) { $followups.Add($p) }
}
if ($followups.Count -gt 0) {
    # Bare commands under a title, so the block can be copied and pasted as-is.
    Write-Output ''
    Write-Output 'Additional inaccessible artefacts (locked from PowerShell - retrieve directly in this Live Response session):'
    foreach ($p in $followups) { Write-Output "getfile `"$p`"" }
}

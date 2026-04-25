# SPDX-License-Identifier: MIT
#
# Run the v1.2.0 SNES loader against a corpus of real cartridges via the
# already-running ``ghidra-mcp`` Docker container. The container ships with
# a current Ghidra install plus the ``ghidra-65816`` processor module and
# the ``ghidra_snes_loader`` extension preinstalled.
#
# This script is a *local* smoke runner. It never commits anything to git
# and never copies a ROM out of the container; the container's own
# ephemeral storage is the only place a binary ROM ever lives.
#
# Usage:
#   pwsh tests/real-rom-smoke.ps1 -RomDir "C:\Users\thele\Downloads\Roms for SNES"
#
# The script prints a per-ROM summary table to stdout and writes the full
# per-ROM MARK output into ``.local-test/<rom-stem>.marks.txt`` for review.

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string] $RomDir,

    [Parameter(Mandatory=$false)]
    [string] $Container = "ghidra-mcp",

    [Parameter(Mandatory=$false)]
    [string] $PostScript = "$PSScriptRoot\PrintRealRomSnapshot.java"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

# Pull a single capture group out of a list of MARK: lines. Returns
# the empty string if no line matched, so the summary table degrades
# gracefully when a marker is missing on a particular ROM.
function Get-MarkValue {
    param(
        [Parameter(Mandatory)] [AllowEmptyCollection()] [string[]] $Lines,
        [Parameter(Mandatory)] [string]   $Pattern
    )
    if (-not $Lines -or $Lines.Count -eq 0) { return "" }
    foreach ($line in $Lines) {
        if ($line -match $Pattern) {
            return $Matches[1]
        }
    }
    return ""
}

if (-not (Test-Path $RomDir)) {
    throw "ROM directory not found: $RomDir"
}
if (-not (Test-Path $PostScript)) {
    throw "Post-script not found: $PostScript"
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
$Outdir = Join-Path $RepoRoot ".local-test"
New-Item -ItemType Directory -Force -Path $Outdir | Out-Null

# 1. Stage the post-script into the container once, under /tmp/scripts.
docker exec $Container mkdir -p /tmp/scripts /tmp/roms /tmp/proj | Out-Null
docker cp $PostScript "${Container}:/tmp/scripts/PrintRealRomSnapshot.java" | Out-Null

# 2. Iterate the ROMs. We fail soft per ROM: a single broken cart should
#    not kill the whole batch run.
$Roms = Get-ChildItem -Path $RomDir -File `
        | Where-Object { $_.Extension -in '.smc', '.sfc', '.swc' } `
        | Sort-Object Length

$Summary = [System.Collections.Generic.List[object]]::new()
foreach ($Rom in $Roms) {
    $stem = [IO.Path]::GetFileNameWithoutExtension($Rom.Name)
    $kb = [int]($Rom.Length / 1024)
    Write-Host ""
    Write-Host "=== $($Rom.Name)  ($kb KiB) ===" -ForegroundColor Cyan

    # Copy the ROM in under a sanitised name. Real cartridge filenames
    # often contain spaces and parentheses (e.g. "Super Mario Kart
    # (USA).sfc") which choke ``bash -c`` quoting on the analyzeHeadless
    # command line. The container only sees this stripped name; the
    # ROM's identity is preserved in the host-side summary table.
    $sanitised = ($Rom.BaseName -replace '[^A-Za-z0-9._-]', '_') + $Rom.Extension
    docker cp $Rom.FullName "${Container}:/tmp/roms/$sanitised" | Out-Null
    # Wipe any prior project so the import is deterministic.
    docker exec $Container rm -rf /tmp/proj/smoke /tmp/proj/smoke.gpr 2>$null | Out-Null

    $logFile = Join-Path $Outdir "$stem.headless.log"
    $marksFile = Join-Path $Outdir "$stem.marks.txt"

    # The Ghidra entrypoint sets up GHIDRA_HOME for us; analyzeHeadless
    # needs an explicit project dir (we use /tmp/proj/smoke) plus the
    # script search path inside the container.
    $cmd = @(
        "/opt/ghidra/support/analyzeHeadless",
        "/tmp/proj", "smoke",
        "-import", "/tmp/roms/$sanitised",
        "-scriptPath", "/tmp/scripts",
        "-postScript", "PrintRealRomSnapshot.java",
        "-deleteProject"
    )
    # Capture both stdout and stderr.
    $raw = docker exec $Container bash -c ($cmd -join " ") 2>&1
    $raw | Out-File -FilePath $logFile -Encoding utf8
    $rc = $LASTEXITCODE

    $marks = @($raw | Select-String -Pattern "MARK:" | ForEach-Object { $_.Line })
    $marks | Out-File -FilePath $marksFile -Encoding utf8
    Write-Host ("  rc={0}  marks={1}  log={2}" -f $rc, $marks.Count, $logFile)

    # Yank the values we want for the summary table.
    $row = [pscustomobject]@{
        ROM            = $Rom.Name
        Size           = "{0,5} KiB" -f $kb
        Title          = (Get-MarkValue $marks 'TITLE "(.+)"')
        Map            = (Get-MarkValue $marks 'MAPMODE = ([0-9a-f]+)')
        Kind           = (Get-MarkValue $marks 'ROMKIND (\S+)')
        Coproc         = (Get-MarkValue $marks 'COPROC (\S+)')
        Functions      = [int](Get-MarkValue $marks 'COUNT FUNCTIONS (\d+)')
        Blocks         = [int](Get-MarkValue $marks 'COUNT BLOCKS (\d+)')
        SymbolsHW      = [int](Get-MarkValue $marks 'COUNT SYMBOLS_HW (\d+)')
        SymbolsTotal   = [int](Get-MarkValue $marks 'COUNT SYMBOLS_TOTAL (\d+)')
        DBROverrides   = [int](Get-MarkValue $marks 'COUNT DBR_OVERRIDES (\d+)')
        DPOverrides    = [int](Get-MarkValue $marks 'COUNT DP_OVERRIDES (\d+)')
        ResetEntry     = (Get-MarkValue $marks 'ENTRY RESET (\S+)')
    }
    $Summary.Add($row)
}

# Print the summary as a table.
Write-Host ""
Write-Host "===== Real-ROM smoke summary =====" -ForegroundColor Green
$Summary | Format-Table -AutoSize ROM, Size, Kind, Coproc, Functions, Blocks, SymbolsHW, DBROverrides, DPOverrides, Title

# Persist the table.
$tableOut = Join-Path $Outdir "summary.txt"
$Summary | Format-Table -AutoSize ROM, Size, Kind, Coproc, Functions, Blocks, SymbolsHW, DBROverrides, DPOverrides, Title `
    | Out-String | Out-File -FilePath $tableOut -Encoding utf8
Write-Host "Wrote $tableOut"

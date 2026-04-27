# SPDX-License-Identifier: MIT
#
# Local integration smoke for the Ghidra SNES stack. This uses synthetic ROMs
# only; no private ROM is required or copied.
#
# Usage:
#   pwsh tests/ghidra-stack-smoke.ps1

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string] $Container = "ghidra-mcp",

    [Parameter(Mandatory=$false)]
    [string] $Processor65816Path = "C:\Users\thele\Projects\ghidra-65816",

    [Parameter(Mandatory=$false)]
    [string] $Spc700Path = "C:\Users\thele\Projects\ghidra-spc700",

    [Parameter(Mandatory=$false)]
    [string] $GradlePath = "/opt/gradle-8.5/bin/gradle"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
$OutDir = Join-Path $RepoRoot ".local-test\stack-smoke"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

function Require-Path {
    param([Parameter(Mandatory)] [string] $Path)
    if (-not (Test-Path $Path)) {
        throw "Required path not found: $Path"
    }
}

Require-Path $Processor65816Path
Require-Path $Spc700Path
Require-Path (Join-Path $RepoRoot "tests\synth-min-lorom.py")
Require-Path (Join-Path $RepoRoot "tests\PrintSnesArtifacts.java")
Require-Path (Join-Path $RepoRoot "tests\ExportSnesStructureJson.java")

Write-Host "== Stage and compile ghidra-65816 ==" -ForegroundColor Cyan
docker exec $Container bash -lc "rm -rf /tmp/ghidra-stack-smoke && mkdir -p /tmp/ghidra-stack-smoke /opt/ghidra/Ghidra/Processors/65816 /opt/ghidra/Ghidra/Processors/SPC700" | Out-Null
docker exec $Container bash -lc "rm -rf /opt/ghidra/Ghidra/Processors/65816/* /opt/ghidra/Ghidra/Processors/SPC700/*" | Out-Null
docker cp (Join-Path $Processor65816Path "Module.manifest") "${Container}:/opt/ghidra/Ghidra/Processors/65816/" | Out-Null
docker cp (Join-Path $Processor65816Path "data") "${Container}:/opt/ghidra/Ghidra/Processors/65816/" | Out-Null
docker exec $Container bash -lc "/opt/ghidra/support/sleigh -a /opt/ghidra/Ghidra/Processors/65816 >/tmp/ghidra-stack-smoke/65816-sleigh.log 2>&1 && test -f /opt/ghidra/Ghidra/Processors/65816/data/languages/65816.sla && test -f /opt/ghidra/Ghidra/Processors/65816/data/languages/65802.sla"

Write-Host "== Stage and compile ghidra-spc700 ==" -ForegroundColor Cyan
docker cp (Join-Path $Spc700Path "Module.manifest") "${Container}:/opt/ghidra/Ghidra/Processors/SPC700/" | Out-Null
docker cp (Join-Path $Spc700Path "data") "${Container}:/opt/ghidra/Ghidra/Processors/SPC700/" | Out-Null
docker exec $Container bash -lc "/opt/ghidra/support/sleigh -a /opt/ghidra/Ghidra/Processors/SPC700 >/tmp/ghidra-stack-smoke/spc700-sleigh.log 2>&1 && test -f /opt/ghidra/Ghidra/Processors/SPC700/data/languages/spc700.sla"

Write-Host "== Build and install local SNES loader ==" -ForegroundColor Cyan
docker exec $Container bash -lc "rm -rf /tmp/ghidra-stack-smoke/SnesLoader /opt/ghidra/Ghidra/Extensions/SnesLoader /opt/ghidra/Ghidra/Extensions/ghidra_snes_loader" | Out-Null
docker cp (Join-Path $RepoRoot "SnesLoader") "${Container}:/tmp/ghidra-stack-smoke/SnesLoader" | Out-Null
docker exec $Container bash -lc "cd /tmp/ghidra-stack-smoke/SnesLoader && JAVA_HOME=/usr/lib/jvm/java-21-openjdk-amd64 '$GradlePath' --no-daemon buildExtension -PGHIDRA_INSTALL_DIR=/opt/ghidra >/tmp/ghidra-stack-smoke/loader-build.log 2>&1 || { tail -n 120 /tmp/ghidra-stack-smoke/loader-build.log; exit 1; }"
docker exec $Container bash -lc 'zip=$(find /tmp/ghidra-stack-smoke/SnesLoader -type f -name "*.zip" ! -name "*-src.zip" | head -n1); test -n "$zip" && unzip -oq "$zip" -d /opt/ghidra/Ghidra/Extensions && find /opt/ghidra/Ghidra/Extensions -maxdepth 2 -name extension.properties | grep -E "(SnesLoader|ghidra_snes_loader)" >/dev/null'

Write-Host "== Import synthetic LoROM through installed SNES loader ==" -ForegroundColor Cyan
$RomPath = Join-Path $OutDir "stack-min-lorom.smc"
py -3.12 (Join-Path $RepoRoot "tests\synth-min-lorom.py") $RomPath | Out-Null
docker exec $Container bash -lc "mkdir -p /tmp/ghidra-stack-smoke/scripts /tmp/ghidra-stack-smoke/rom /tmp/ghidra-stack-smoke/proj" | Out-Null
docker cp (Join-Path $RepoRoot "tests\PrintSnesArtifacts.java") "${Container}:/tmp/ghidra-stack-smoke/scripts/" | Out-Null
docker cp $RomPath "${Container}:/tmp/ghidra-stack-smoke/rom/stack-min-lorom.smc" | Out-Null
docker exec $Container bash -lc "rm -rf /tmp/ghidra-stack-smoke/proj/smoke /tmp/ghidra-stack-smoke/proj/smoke.gpr && /opt/ghidra/support/analyzeHeadless /tmp/ghidra-stack-smoke/proj smoke -import /tmp/ghidra-stack-smoke/rom/stack-min-lorom.smc -scriptPath /tmp/ghidra-stack-smoke/scripts -postScript PrintSnesArtifacts.java -deleteProject >/tmp/ghidra-stack-smoke/headless.log 2>&1"

$LogPath = Join-Path $OutDir "headless.log"
$MarksPath = Join-Path $OutDir "marks.txt"
docker cp "${Container}:/tmp/ghidra-stack-smoke/headless.log" $LogPath | Out-Null
Select-String -Path $LogPath -Pattern "MARK:" | ForEach-Object { $_.Line } | Out-File -FilePath $MarksPath -Encoding utf8

$Required = @(
    "MARK: LANGUAGE 65816:LE:16:default",
    "MARK: MAPMODE @ 0000ffd5 = 20",
    "MARK: VECTOR vector_RESET @ 0000fffc",
    "MARK: ENTRY RESET 00008000"
)

$Marks = Get-Content $MarksPath
foreach ($Needle in $Required) {
    if (-not ($Marks | Select-String -SimpleMatch $Needle)) {
        throw "Missing expected marker: $Needle"
    }
}

Write-Host "== Export payload-free structure JSON ==" -ForegroundColor Cyan
docker cp (Join-Path $RepoRoot "tests\ExportSnesStructureJson.java") "${Container}:/tmp/ghidra-stack-smoke/scripts/" | Out-Null
docker exec $Container bash -lc "rm -rf /tmp/ghidra-stack-smoke/proj/export /tmp/ghidra-stack-smoke/proj/export.gpr && /opt/ghidra/support/analyzeHeadless /tmp/ghidra-stack-smoke/proj export -import /tmp/ghidra-stack-smoke/rom/stack-min-lorom.smc -scriptPath /tmp/ghidra-stack-smoke/scripts -postScript ExportSnesStructureJson.java -deleteProject >/tmp/ghidra-stack-smoke/export.log 2>&1"
$ExportLogPath = Join-Path $OutDir "export.log"
$ExportJsonPath = Join-Path $OutDir "structure.json"
docker cp "${Container}:/tmp/ghidra-stack-smoke/export.log" $ExportLogPath | Out-Null
$jsonLine = Get-Content $ExportLogPath | Select-String -Pattern 'JSON: ' | Select-Object -Last 1
if (-not $jsonLine) {
    throw "No JSON export marker found: $ExportLogPath"
}
if ($jsonLine.Line -notmatch 'JSON:\s*(\{.*\})') {
    throw "JSON export marker did not contain an object: $($jsonLine.Line)"
}
$json = $Matches[1]
$summary = $json | ConvertFrom-Json
if ($summary.language -ne "65816:LE:16:default") {
    throw "Unexpected export language: $($summary.language)"
}
if ($summary.map_mode -ne "20") {
    throw "Unexpected export map mode: $($summary.map_mode)"
}
if ($summary.counts.functions -lt 1) {
    throw "Expected at least one exported function"
}
if ($summary.counts.functions_discovered_direct_calls -lt 1) {
    throw "Expected SNES Function Discovery to create at least one direct-call function"
}
$summary | ConvertTo-Json -Depth 20 | Out-File -FilePath $ExportJsonPath -Encoding utf8

Write-Host "Stack smoke passed. Logs written to $OutDir" -ForegroundColor Green

# SPDX-License-Identifier: MIT
#
# Export payload-free indirect-flow and pointer-table candidates for a local
# private ROM. The output contains only addresses, candidate kinds, and counts.
#
# Usage:
#   pwsh tests/export-flow-candidates.ps1 -RomPath "C:\path\game.sfc"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string] $RomPath,

    [Parameter(Mandatory=$false)]
    [string] $OutPath = "",

    [Parameter(Mandatory=$false)]
    [string] $Container = "ghidra-mcp"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

if (-not (Test-Path $RomPath)) {
    throw "ROM path not found: $RomPath"
}

$RepoRoot = Split-Path -Parent $PSScriptRoot
$OutDir = Join-Path $RepoRoot ".local-test\flow-candidates"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if ([string]::IsNullOrWhiteSpace($OutPath)) {
    $stem = [IO.Path]::GetFileNameWithoutExtension($RomPath) -replace '[^A-Za-z0-9_.-]', '_'
    $OutPath = Join-Path $OutDir "$stem.flow-candidates.json"
}

$safeStem = [IO.Path]::GetFileNameWithoutExtension($OutPath) -replace '[^A-Za-z0-9_.-]', '_'
$runId = [Guid]::NewGuid().ToString("N")
$containerWork = "/tmp/snes-flow-$runId"
$headlessLog = Join-Path $OutDir "$safeStem.headless.log"

try {
    docker exec $Container bash -lc "rm -rf $containerWork && mkdir -p $containerWork/scripts $containerWork/rom $containerWork/proj" | Out-Null
    docker cp (Join-Path $RepoRoot "tests\ExportSnesFlowCandidates.java") "${Container}:$containerWork/scripts/" | Out-Null
    docker cp $RomPath "${Container}:$containerWork/rom/input.sfc" | Out-Null

    $raw = docker exec $Container bash -lc "/opt/ghidra/support/analyzeHeadless $containerWork/proj flow -import $containerWork/rom/input.sfc -scriptPath $containerWork/scripts -postScript ExportSnesFlowCandidates.java -deleteProject" 2>&1
    $raw | Out-File -FilePath $headlessLog -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        throw "analyzeHeadless failed; see $headlessLog"
    }

    $jsonLine = $raw | Select-String -Pattern '^INFO  ExportSnesFlowCandidates.java> JSON: ' | Select-Object -Last 1
    if (-not $jsonLine) {
        $jsonLine = $raw | Select-String -Pattern '^JSON: ' | Select-Object -Last 1
    }
    if (-not $jsonLine -or $jsonLine.Line -notmatch 'JSON:\s*(\{.*\})') {
        throw "No JSON marker found; see $headlessLog"
    }

    $Matches[1] | ConvertFrom-Json | ConvertTo-Json -Depth 20 |
        Out-File -FilePath $OutPath -Encoding utf8
    Write-Host "Wrote $OutPath"
}
finally {
    docker exec $Container bash -lc "rm -rf $containerWork" 2>$null | Out-Null
}

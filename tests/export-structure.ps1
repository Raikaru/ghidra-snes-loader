# SPDX-License-Identifier: MIT
#
# Export a payload-free structural JSON summary for a local SNES ROM import.
# The JSON contains loader/decompiler structure only and must not contain ROM
# bytes, decoded content, screenshots, assets, scripts, maps, audio, or saves.
#
# Usage:
#   pwsh tests/export-structure.ps1 -RomPath "C:\path\game.sfc"

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
$OutDir = Join-Path $RepoRoot ".local-test\structure-export"
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

if ([string]::IsNullOrWhiteSpace($OutPath)) {
    $stem = [IO.Path]::GetFileNameWithoutExtension($RomPath)
    $OutPath = Join-Path $OutDir "$stem.structure.json"
}

$safeStem = [IO.Path]::GetFileNameWithoutExtension($OutPath) -replace '[^A-Za-z0-9_.-]', '_'
$runId = [Guid]::NewGuid().ToString("N")
$containerWork = "/tmp/snes-structure-$runId"
$headlessLog = Join-Path $OutDir "$safeStem.headless.log"

try {
    docker exec $Container bash -lc "rm -rf $containerWork && mkdir -p $containerWork/scripts $containerWork/rom $containerWork/proj" | Out-Null
    docker cp (Join-Path $RepoRoot "tests\ExportSnesStructureJson.java") "${Container}:$containerWork/scripts/" | Out-Null
    docker cp $RomPath "${Container}:$containerWork/rom/input.sfc" | Out-Null

    $raw = docker exec $Container bash -lc "/opt/ghidra/support/analyzeHeadless $containerWork/proj export -import $containerWork/rom/input.sfc -scriptPath $containerWork/scripts -postScript ExportSnesStructureJson.java -deleteProject" 2>&1
    $raw | Out-File -FilePath $headlessLog -Encoding utf8
    if ($LASTEXITCODE -ne 0) {
        throw "analyzeHeadless failed; see $headlessLog"
    }

    $jsonLine = $raw | Select-String -Pattern '^INFO  ExportSnesStructureJson.java> JSON: ' | Select-Object -Last 1
    if (-not $jsonLine) {
        $jsonLine = $raw | Select-String -Pattern '^JSON: ' | Select-Object -Last 1
    }
    if (-not $jsonLine) {
        throw "No JSON marker found; see $headlessLog"
    }

    if ($jsonLine.Line -notmatch 'JSON:\s*(\{.*\})') {
        throw "JSON marker did not contain an object; see $headlessLog"
    }
    $json = $Matches[1]
    $json | ConvertFrom-Json | ConvertTo-Json -Depth 20 | Out-File -FilePath $OutPath -Encoding utf8

    Write-Host "Wrote $OutPath"
}
finally {
    docker exec $Container bash -lc "rm -rf $containerWork" 2>$null | Out-Null
}

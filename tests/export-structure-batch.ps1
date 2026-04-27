# SPDX-License-Identifier: MIT
#
# Run payload-free structural exports for a private local ROM set.
# Outputs stay under .local-test/structure-export by default and must not be
# committed. The summary records loader/decompiler structure only.
#
# Usage:
#   pwsh tests/export-structure-batch.ps1 -RomDir "C:\path\to\roms" -NamePattern "*Shin Megami Tensei*.sfc"

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [string] $RomDir = "",

    [Parameter(Mandatory=$false)]
    [string[]] $RomPath = @(),

    [Parameter(Mandatory=$false)]
    [string] $NamePattern = "*.sfc",

    [Parameter(Mandatory=$false)]
    [string] $OutDir = "",

    [Parameter(Mandatory=$false)]
    [string] $Container = "ghidra-mcp",

    [Parameter(Mandatory=$false)]
    [ValidateRange(1, 16)]
    [int] $Throttle = 2
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$RepoRoot = Split-Path -Parent $PSScriptRoot
if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $RepoRoot ".local-test\structure-export"
}
New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$roms = @()
if (-not [string]::IsNullOrWhiteSpace($RomDir)) {
    if (-not (Test-Path $RomDir)) {
        throw "ROM directory not found: $RomDir"
    }
    $roms += Get-ChildItem -Path $RomDir -File -Filter $NamePattern | Sort-Object Name | Select-Object -ExpandProperty FullName
}
$roms += $RomPath
$roms = @($roms | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object {
    $resolved = Resolve-Path -LiteralPath $_ -ErrorAction Stop
    $resolved.Path
} | Sort-Object -Unique)

if ($roms.Count -eq 0) {
    throw "No ROMs matched. Provide -RomDir/-NamePattern or -RomPath."
}

$exportScript = Join-Path $RepoRoot "tests\export-structure.ps1"
$jobs = New-Object System.Collections.Generic.List[object]
$results = New-Object System.Collections.Generic.List[object]

function ConvertTo-SafeStem([string] $path) {
    $base = [IO.Path]::GetFileNameWithoutExtension($path) -replace '[^A-Za-z0-9_.-]', '_'
    $bytes = [Text.Encoding]::UTF8.GetBytes($path.ToLowerInvariant())
    $hash = [Security.Cryptography.SHA256]::HashData($bytes)
    $hashText = ([BitConverter]::ToString($hash) -replace '-', '').Substring(0, 12).ToLowerInvariant()
    return "$base.$hashText"
}

function Read-ExportSummary([string] $rom, [string] $inputId, [string] $jsonPath, [string] $status, [string] $errorText) {
    if ($status -ne "ok") {
        return [pscustomobject]@{
            rom = [IO.Path]::GetFileName($rom)
            input_id = $inputId
            structure_json = [IO.Path]::GetFileName($jsonPath)
            status = $status
            error = $errorText
        }
    }
    if (-not (Test-Path -LiteralPath $jsonPath)) {
        return [pscustomobject]@{
            rom = [IO.Path]::GetFileName($rom)
            input_id = $inputId
            structure_json = [IO.Path]::GetFileName($jsonPath)
            status = "failed"
            error = "Export JSON not found: $jsonPath"
        }
    }

    $json = Get-Content -LiteralPath $jsonPath -Raw | ConvertFrom-Json
    $defaultRomBlocks = @($json.memory_blocks | Where-Object {
        $_.name -like "rom_*" -and $_.type -eq "Default"
    }).Count
    $byteMappedBlocks = @($json.memory_blocks | Where-Object {
        $_.type -eq "Byte Mapped"
    }).Count
    $vectorFunctions = @($json.vectors | Where-Object {
        -not [string]::IsNullOrWhiteSpace($_.function)
    }).Count

    return [pscustomobject]@{
        rom = [IO.Path]::GetFileName($rom)
        input_id = $inputId
        structure_json = [IO.Path]::GetFileName($jsonPath)
        status = "ok"
        language = $json.language
        compiler = $json.compiler
        map_mode = $json.map_mode
        memory_blocks = $json.counts.memory_blocks
        default_rom_blocks = $defaultRomBlocks
        byte_mapped_blocks = $byteMappedBlocks
        functions = $json.counts.functions
        functions_discovered_direct_calls = $json.counts.functions_discovered_direct_calls
        symbols_total = $json.counts.symbols_total
        symbols_hw_primary = $json.counts.symbols_hw_primary
        indirect_flow_candidates = $json.counts.indirect_flow_candidates
        apu_port_reference_instructions = $json.counts.apu_port_reference_instructions
        hw_reference_instructions = $json.counts.hw_reference_instructions
        unresolved_call_instructions = $json.counts.unresolved_call_instructions
        dbr_override_instructions = $json.counts.dbr_override_instructions
        dp_override_instructions = $json.counts.dp_override_instructions
        vector_symbols = @($json.vectors).Count
        vector_functions = $vectorFunctions
    }
}

foreach ($rom in $roms) {
    while (@($jobs | Where-Object { $_.State -eq "Running" }).Count -ge $Throttle) {
        $done = Wait-Job -Job $jobs -Any
        $output = Receive-Job -Job $done -ErrorAction Continue
        $jobs.Remove($done) | Out-Null
        $results.Add($output) | Out-Null
        Remove-Job -Job $done
    }

    $stem = ConvertTo-SafeStem $rom
    $jsonPath = Join-Path $OutDir "$stem.structure.json"
    $jobs.Add((Start-Job -ArgumentList $exportScript,$rom,$jsonPath,$Container -ScriptBlock {
        param($scriptPath, $romPath, $outPath, $containerName)
        try {
            Remove-Item -LiteralPath $outPath -Force -ErrorAction SilentlyContinue
            $childOutput = & pwsh -NoProfile -File $scriptPath -RomPath $romPath -OutPath $outPath -Container $containerName 2>&1
            if ($LASTEXITCODE -ne 0) {
                $tail = @($childOutput | Select-Object -Last 8) -join " "
                throw "export-structure.ps1 exited with code $LASTEXITCODE. $tail"
            }
            [pscustomobject]@{
                rom = $romPath
                input_id = [IO.Path]::GetFileNameWithoutExtension($outPath) -replace '\.structure$', ''
                json = $outPath
                status = "ok"
                error = ""
            }
        }
        catch {
            [pscustomobject]@{
                rom = $romPath
                input_id = [IO.Path]::GetFileNameWithoutExtension($outPath) -replace '\.structure$', ''
                json = $outPath
                status = "failed"
                error = $_.Exception.Message
            }
        }
    })) | Out-Null
}

while ($jobs.Count -gt 0) {
    $done = Wait-Job -Job $jobs -Any
    $output = Receive-Job -Job $done -ErrorAction Continue
    $jobs.Remove($done) | Out-Null
    $results.Add($output) | Out-Null
    Remove-Job -Job $done
}

$summary = foreach ($result in $results) {
    Read-ExportSummary $result.rom $result.input_id $result.json $result.status $result.error
}

$summaryPath = Join-Path $OutDir "batch-summary.json"
$summary | Sort-Object rom | ConvertTo-Json -Depth 10 | Out-File -LiteralPath $summaryPath -Encoding utf8
$summary | Sort-Object rom | Format-Table -AutoSize

$failures = @($summary | Where-Object { $_.status -ne "ok" })
if ($failures.Count -gt 0) {
    throw "$($failures.Count) export(s) failed; see $summaryPath"
}

Write-Host "Wrote $summaryPath"

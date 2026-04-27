# Ghidra Stack Workflow

This repo is the SNES loader half of the local Ghidra stack. Use it with:

- `ghidra-65816` for the main SNES CPU language.
- `ghidra-snes-loader` for ROM import, memory maps, vectors, hardware labels, and DBR/DP analysis.
- `ghidra-spc700` for SPC700/APU blobs extracted or observed locally.

## SMT-Family ROMs As Validation Targets

SMT1, SMT2, and SMT if... can be used as local real-ROM regression cases, but
they are not committed test fixtures.

Allowed in this repo:

- import success/failure notes;
- ROM kind, map mode, coprocessor classification;
- memory block, vector, function, symbol, DBR/DP counts;
- labels, addresses, and behavior hypotheses;
- local-only `.local-test/` logs and marker files.

Not allowed:

- ROM files;
- decoded text;
- copied disassembly blocks;
- screenshots of copyrighted graphics;
- maps, scripts, samples, save payloads, or raw byte ranges.

## Basic Local Flow

1. Make sure `ghidra-mcp` is running and has Ghidra at `/opt/ghidra`.
2. Stage or install the current `ghidra-65816` processor.
3. Build/install the current loader extension if loader code changed.
4. Compile/stage `ghidra-spc700` if APU work is involved.
5. Run synthetic stack smoke:

   ```powershell
   .\tests\ghidra-stack-smoke.ps1
   ```

   This builds and installs the local loader in the container before import, so
   it does not silently test a stale extension.

6. Run local real-ROM smoke when validating real cartridges:

   ```powershell
   .\tests\real-rom-smoke.ps1 -RomDir "C:\path\to\local\roms"
   ```

7. Export a payload-free structural JSON summary when a port repo needs
   machine-readable evidence:

   ```powershell
   .\tests\export-structure.ps1 -RomPath "C:\path\to\local\rom.sfc"
   ```

8. Batch-export a private validation set when comparing related games:

   ```powershell
   .\tests\export-structure-batch.ps1 -RomDir "C:\path\to\local\roms" -NamePattern "*Shin Megami Tensei*.sfc"
   ```

9. Record findings with `docs/NOTES-TEMPLATE.md`.

## What To Check On SMT-Family ROMs

For loader/processor validation, high-value observations are:

- language is `65816:LE:16:default`;
- LoROM/HiROM classification matches the header;
- reset, NMI, IRQ, BRK, COP vectors are labeled;
- RESET function is created;
- hardware register labels appear in primary and mirrored banks;
- DBR/DP analyzer produces non-default observations in real code;
- decompiler output uses native memory references rather than synthetic byte churn;
- SPC upload/sound command routines are locatable from the 65816 side.

## Payload-Free Structure Export

`tests/ExportSnesStructureJson.java` emits JSON with:

- program/language/compiler identifiers;
- map mode;
- vector symbol addresses;
- vector targets and whether Ghidra has a function at each target;
- memory block names/ranges/types/sizes;
- counts for functions, blocks, symbols, hardware symbols, and DBR/DP analyzer coverage.

It does not emit ROM bytes, decoded text, disassembly bodies, graphics,
screenshots, audio, maps, scripts, or saves. Output belongs under `.local-test/`
or another ignored/local path.

The wrapper removes the copied ROM from its temporary `/tmp/snes-structure-*`
workspace when it exits. The batch wrapper writes a compact
`batch-summary.json` with counts only, suitable for local comparison across
private ROMs.

If an observation points to APU code, analyze the SPC700 blob separately with `ghidra-spc700`; do not turn this repo into an SMT1 decomp notes store.

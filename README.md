# ghidra-snes-loader

[![Build Ghidra extension](https://github.com/Raikaru/ghidra-snes-loader/actions/workflows/build-extension.yml/badge.svg?branch=master)](https://github.com/Raikaru/ghidra-snes-loader/actions/workflows/build-extension.yml)

SNES ROM loader extension for [Ghidra](https://ghidra-sre.org/), bundled with a
DBR/DP tracking analyser tuned for the 65816 architecture. Originally based on
`achan1989/ghidra-snes-loader` (archived upstream) and re-modernised for the
current Ghidra release line.

This is the **loader half** of the setup. It depends on the companion
65816 processor module:

- [`ghidra-65816`](https://github.com/Raikaru/ghidra-65816) — language ID
  `65816:LE:16:default`. Without it the loader has no language to bind to.

## What it does

### ROM detection

- Auto-detects **LoROM, HiROM, ExHiROM** with and without an optional 512-byte
  SMC copier header.
- Decodes the cartridge header at `$00:FFC0` / `$7F:FFC0` and surfaces the
  title, region, ROM/SRAM size and version code.
- Recognises the **coprocessor / cartridge add-on** advertised in the
  cartridge-type byte: SA-1, SuperFX (GSU-1/2), S-DD1, OBC-1, S-RTC, Cx4,
  SPC7110, ST010/011/018, plus the older DSP family.

### Memory map

- Maps every ROM bank into the 65816 24-bit bus (LoROM, HiROM, ExHiROM aware).
- Maps WRAM (`$7E:0000-$7F:FFFF`) and the LowRAM mirror at `$00:0000-$00:1FFF`,
  with byte-mapped mirrors in every bank `$01-$3F` and `$80-$BF` so
  code that runs with a non-zero DBR resolves direct/absolute reads
  cleanly.
- Maps the hardware-register window `$00:2000-$00:43FF` (covers MSU-1 plus the
  PPU/CPU/APU/DMA windows in one block), again mirrored into banks
  `$01-$3F` and `$80-$BF`.
- Maps cartridge SRAM at the canonical LoROM (`$70:0000`) or HiROM (`$30:6000`)
  location when the header advertises any.

### Symbolisation

- Names every PPU register (`INIDISP`, `BGMODE`, `VMADDL`, `CGADD`, …), CPU
  register (`NMITIMEN`, `WRMPYA`, `RDDIVL`, …) and all 8 DMA channels
  (`DMAP0`, `BBAD0`, `A1TL0`, …) with a per-cell EOL comment so the disassembly
  reads symbolically instead of as bare addresses.
- Names the **MSU-1 / SD2SNES** streaming registers at `$00:2000-$00:2007`
  (status/identifier on read, seek and audio control on write).
- Names the **SA-1 / SuperFX / S-DD1** coprocessor register windows when the
  header advertises that chip.
- Applies a `SnesCartridgeHeader` data type at `$00:FFC0` so the cart metadata
  is decoded inline in the listing.
- Resolves and names every native- and emulation-mode interrupt vector
  (`vector_RESET`, `vector_NMI_native`, `isr_irq_native`, …) and creates a
  function at each target so analysis starts from real entry points.

### DBR / DP tracking analyser

A bundled `SNES DBR/DP Tracker` analyser walks the disassembly looking for
common 65816 idioms and writes the resulting Data Bank Register / Direct Page
values into the program context so the decompiler can resolve absolute and
direct-page addresses correctly. Patterns recognised today:

| Pattern                            | Effect                       |
| ---------------------------------- | ---------------------------- |
| `PHK ; PLB`                        | `DBR := PBR` (current bank)  |
| `LDA #imm8 ; PHA ; PLB`            | `DBR := imm`                 |
| `PEA #imm16 ; PLB ; PLB`           | `DBR := imm.high`            |
| `LDA #imm16 ; TCD`                 | `DP  := imm`                 |
| `LDA #imm16 ; PHA ; PLD`           | `DP  := imm`                 |
| `PEA #imm16 ; PLD`                 | `DP  := imm`                 |

Every value is committed forward to the end of the containing function (or
until the next conflicting write), so e.g. a `LDA $1234,X` that follows a
`PHK ; PLB` decompiles as a load from `<currentBank>:1234,X` instead of from
the loader's tracked default of `$00:1234,X`.

## Build

The extension is built with Gradle and a local Ghidra installation. Set
`GHIDRA_INSTALL_DIR` to the unpacked Ghidra root.

Linux / macOS:

```bash
cd SnesLoader
GHIDRA_INSTALL_DIR=/abs/path/to/ghidra ./gradlew buildExtension
```

Windows (PowerShell):

```powershell
cd SnesLoader
$env:GHIDRA_INSTALL_DIR = 'C:\abs\path\to\ghidra'
.\gradlew.bat buildExtension
```

The output is `SnesLoader/dist/ghidra_<version>_PUBLIC_<date>_ghidra_snes_loader.zip`.

## Install

1. Install [`ghidra-65816`](https://github.com/Raikaru/ghidra-65816) into
   `Ghidra/Processors/65816` and run `support/sleigh -a` once to compile the
   `.slaspec` to `.sla`.
2. In Ghidra, *File* → *Install Extensions* → *+* → pick the zip above. Restart.
3. Open any `.smc`/`.sfc`/`.swc` file: it should pick up automatically as a
   *SNES ROM* with the 65816 language.

Without step 1, the loader has nothing to bind to and import will silently
fall back to a different language.

## Loader options

Visible at import time and via the headless `-loader-snes*` command-line
flags. All default to **on**.

| Option                                                  | CLI flag                |
| ------------------------------------------------------- | ----------------------- |
| Map SNES hardware registers                             | `-snesHwRegs`           |
| Mark interrupt vectors                                  | `-snesVectors`          |
| Apply Cartridge Header datatype                         | `-snesHeader`           |
| Map LowRAM mirror at `$00:0000` (and all bank mirrors)  | `-snesLowRamMirror`     |
| Map cartridge SRAM (when present)                       | `-snesSram`             |
| Label MSU-1 streaming registers                         | `-snesMsu1`             |
| Label coprocessor registers (SA-1, GSU)                 | `-snesCoproc`           |
| Mirror hardware-register labels into all banks          | `-snesMirrorHwLabels`   |

## Continuous integration

The `Build Ghidra extension` workflow runs on every push and pull
request, on **`ubuntu-latest` and `windows-latest`** in parallel:

1. Downloads the requested Ghidra release.
2. Clones the companion [`ghidra-65816`](https://github.com/Raikaru/ghidra-65816)
   processor module and compiles its SLEIGH spec (both `65816` and `65802`).
3. Builds the loader as a Ghidra extension zip with Gradle 8.5 / JDK 21.
4. Installs the extension into the Ghidra checkout.
5. On Linux only, runs **three behavioural smoke tests**, each
   synthesised on the fly (no committed ROM blobs) and run through
   `analyzeHeadless` with `tests/PrintSnesArtifacts.java` as the
   post-script:

   | ROM                       | What it pins                                                                                                                                       |
   | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------- |
   | `synth-min-lorom.py`      | LoROM detection, every vector label, bank-mirror blocks, mirrored `NMITIMEN @ $00/$01/$3F:4200`, `Reset` function entry, `ctx_E/M/X=1` at `$00:8000`. |
   | `synth-idiom-lorom.py`    | DBR/DP analyser correctness: `LDA #$80; PHA; PLB` propagates `DBR=$80` to `$00:8009`, `LDA #$1234; TCD` propagates `DP=$1234` to `$00:8012`.        |
   | `synth-min-hirom.py`      | HiROM mapping: bank-`$C0` primary block + `$00:8000` and `$80:8000` upper-half mirrors, map-mode byte `$21` at `$00:FFD5`.                          |

A missing marker fails the build and uploads the headless log, the
marker file, and the synthesised ROM as a `smoke-test-*` artefact for
offline diagnosis. The Windows job verifies that the extension zip
builds cleanly under Git-Bash + Gradle's Windows shims, which is where
most user-visible packaging issues have historically appeared.

This gives a regression test for the loader, the DBR/DP analyser, the
HiROM mapper, the mirror-block construction, and the per-vector
context overrides — without shipping any binary ROM in the repo.

## Local validation workflows

- `docs/GHIDRA-STACK-WORKFLOW.md` describes how to use this loader with
  `ghidra-65816` and `ghidra-spc700`.
- `tests/ghidra-stack-smoke.ps1` compiles the local 65816 and SPC700 modules
  inside the `ghidra-mcp` container, builds/installs the local SNES loader,
  and imports a synthetic LoROM through that loader.
- `tests/real-rom-smoke.ps1` can sweep a local private ROM directory and write
  local-only marker summaries under `.local-test/`; these may include short
  instruction text markers and must not be committed.
- `tests/export-structure.ps1` runs a local import and writes a payload-free
  structural JSON summary for downstream validation notes.
- `docs/SMT1-VALIDATION-SEEDS.md` lists high-value real-ROM validation
  questions without making SMT1 a committed fixture.

Real games such as SMT1 are validation targets only. Do not commit ROMs,
decoded text, copied disassembly, screenshots, graphics, audio samples, maps,
scripts, save payloads, or raw byte ranges.

## Provenance

Originally based on
[`achan1989/ghidra-snes-loader`](https://github.com/achan1989/ghidra-snes-loader)
(archived upstream) under MIT. This fork adds cartridge add-on detection, the
DBR/DP tracking analyser, MSU-1 / SA-1 / SuperFX / S-DD1 register labels, an
ExHiROM-aware memory map, and a refreshed cartridge-header datatype.

Released under the original MIT license — see [`LICENSE`](LICENSE).

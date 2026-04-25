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

The `Build Ghidra extension` workflow runs on every push and pull request:

1. Downloads the requested Ghidra release.
2. Clones the companion [`ghidra-65816`](https://github.com/Raikaru/ghidra-65816)
   processor module and compiles its SLEIGH spec.
3. Builds the loader as a Ghidra extension zip.
4. Installs the extension into the Ghidra checkout.
5. Synthesizes a 128 KiB LoROM via `tests/synth-min-lorom.py` and runs
   `analyzeHeadless` against it with `tests/PrintSnesArtifacts.java` as
   the post-script. The job greps the script's output for a fixed list of
   `MARK:` lines (vector labels, bank mirrors, mirrored hardware-register
   labels, the `Reset` function entry point, the language ID). A missing
   marker fails the build and uploads the headless log + ROM image as a
   `smoke-test-*` artefact for offline diagnosis.

This gives a regression test for the loader, the DBR/DP analyser, the
mirror-block construction, and the per-vector context overrides without
shipping any binary ROM in the repo.

## Provenance

Originally based on
[`achan1989/ghidra-snes-loader`](https://github.com/achan1989/ghidra-snes-loader)
(archived upstream) under MIT. This fork adds cartridge add-on detection, the
DBR/DP tracking analyser, MSU-1 / SA-1 / SuperFX / S-DD1 register labels, an
ExHiROM-aware memory map, and a refreshed cartridge-header datatype.

Released under the original MIT license — see [`LICENSE`](LICENSE).

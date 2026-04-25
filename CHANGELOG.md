# Changelog

All notable changes to this loader extension are documented here. The
versioning follows [SemVer](https://semver.org/) for the extension's
`extension.properties`.


## [1.2.2] — 2026-04-25

Expanded coprocessor coverage: GSU (SuperFX) RAM mapping, SA-1
BW-RAM mapping, S-DD1 register window, and DSP-x detection for
cartridges that don't advertise their chip in the standard header
byte (e.g. Super Bowling / DSP-2). 18/18 on the real-ROM corpus.

### Added
- **GSU (SuperFX) RAM and vectors.** 64 KiB RAM block at
  `$70:0000-$70:FFFF` with a labeled vector table, separate from
  SNES WRAM. Verified on Star Fox, Yoshi's Island, and Doom (GSU2).
- **SA-1 BW-RAM mapping.** 256 KiB BW-RAM at `$40-$43:0000-FFFF`
  with per-bank byte-mapped mirrors in `$44-$4F` and the low-memory
  window at `$00-$3F/$80-$BF:6000-$7FFF` (with per-bank mirrors
  matching the LowRAM/hwregs pattern). Verified on Super Mario RPG.
- **S-DD1 register window.** Extended `HW_REGS_LEN` from `0x2400` to
  `0x3000` so the S-DD1 I/O registers at `$00:4800-$00:4807` are
  covered by the primary hwregs block. Star Ocean now reports 214
  hardware symbols (was 208).
- **DSP-x detection for non-standard headers.** Some early DSP games
  (Super Bowling / DSP-2) set cartridge type byte `0x00`, which the
  standard SNES header rules treat as plain ROM. Added a title-based
  override and a general rule: when low nibble < 3 but high nibble
  != 0, still return the coprocessor from the high nibble.
- **`docs/SMOKE-RUN.md`** documenting the Docker-based real-ROM smoke
  test workflow for contributors.
- **CI: synthetic smoke tests** now run on push to master, preserving
  the existing 3-ROM synth-min-LoROM / idiom-LoROM / min-HiROM suite.

### Fixed
- **GSU_RAM_LEN was 0x100000 (1 MiB)** overlapping the WRAM block at
  `$7E:0000-$7F:FFFF`. Corrected to `0x10000` (64 KiB).
- **SA-1 BW-RAM mirrors** used `SA1_BWRAM_LEN` (256 KiB) per individual
  bank, creating 4-bank overlapping blocks. Each mirror now uses
  `0x10000` (64 KiB) per individual bank.

### Changed
- `HW_REGS_LEN` increased from `0x2400` to `0x3000` to cover
  coprocessor I/O at `$00:4800-$00:4FFF`.
- `SnesHeader.getCoprocessor()` refactored into three helper methods
  (`decodeCoprocessorFamily`, `decodeCustomCoprocessor`,
  `decodeDspOverrideByTitle`) for clarity.
- Smoke marker `PrintRealRomSnapshot.classifyCoprocessor()` synced
  with `SnesHeader` logic (accepts ROM title for DSP override).

[1.2.2]: https://github.com/Raikaru/ghidra-snes-loader/releases/tag/v1.2.2

## [1.2.1] — 2026-04-25

Cartridge-corpus pass: every fix in this release is the direct result
of running the loader against an 11-cartridge real-ROM corpus
(EarthBound, Final Fantasy III, Mega Man X2, Star Fox, Star Ocean,
Super Mario Kart, Super Mario RPG, Super Mario World, Super Mario
World 2 — Yoshi's Island, Tales of Phantasia, The Legend of Zelda: A
Link to the Past) inside the GhidraMCP Docker container via the
`tests/real-rom-smoke.ps1` runner.

### Fixed

- **SA-1 cartridges now load.** The `SnesHeader.looksValid()` heuristic
  rejected map-mode `$23` / `$33` (the SA-1-specific LoROM variant)
  because the low-nibble allow-list was missing `3`. As a result every
  SA-1 cartridge -- Super Mario RPG, Kirby Super Star, Kirby's Dream
  Land 3, Mario's Super Picross, Marvelous, ... -- failed import with
  *"No load spec found"*. Added `$23/$33` to `looksValid()`,
  `isLoRomMode()`, and a new `isSa1Mode()` predicate so the loader
  recognises and labels them. Verified end-to-end on Super Mario RPG
  (4 MiB SA-1).
- **SPC7110 cartridges no longer crash the loader.** Map-mode `$3A`
  (HiROM-SPC7110) was likewise rejected by `looksValid()`. Worse, when
  the LoROM-offset header at `$7FC0` happened to checksum-complement
  by coincidence (Star Ocean and Far East of Eden Zero both do), the
  loader picked LoROM and then threw
  `AddressOutOfBoundsException: Offset must be between 0x0 and 0xffffff,
  got 0x1008000 instead!` from `LoRomLoader.busAddressesFor()` because
  the file is 6 MiB but LoROM's bus only addresses the first 4 MiB.
  Added `$3A` to `looksValid()`/`isHiRomMode()`/`isSpc7110Mode()`, and
  capped `LoRomLoader` and `HiRomLoader` at their 4 MiB ceiling with
  a one-shot `MessageLog` warning. Verified on Star Ocean (6 MiB).
- **Cart-type → coprocessor mapping was off by one.** The original
  achan1989 decoder treated high-nibble `0` as "no chip" and shifted
  every other family down by one, so every SuperFX cartridge (Star
  Fox, Yoshi's Island, Doom, Vortex, ...) was reported as a DSP-1
  cart, every OBC-1 cart was reported as GSU, and so on. Re-aligned
  the high-nibble switch to the SNESdev-wiki canonical layout
  (`0=DSP, 1=GSU, 2=OBC1, 3=SA1, 4=SDD1, 5=SRTC, F=Custom`). Now Star
  Fox, Yoshi's Island, and Mega Man X2 (Cx4) all classify correctly.
- **Tie-break between coincidental LoROM and real HiROM.** When both
  candidates pass validation, `pickBestMatch` previously preferred
  LoROM unconditionally as a stylistic choice. That silently truncated
  any 6 MiB SPC7110/ExHiROM cartridge that happened to also pass
  LoROM-at-`$7FC0`. The picker now penalises LoROM by 50 points when
  the file exceeds the LoROM 4 MiB ceiling, so HiROM/ExHiROM wins on
  oversized cartridges.

### Added

- `tests/real-rom-smoke.ps1` -- a Windows/PowerShell runner that drives
  the GhidraMCP Docker container against a host-side directory of SNES
  ROMs, dumps a per-cartridge `MARK:` snapshot via `tests/PrintRealRomSnapshot.java`,
  and prints a side-by-side summary table (kind, coprocessor, function
  count, hardware-register symbol count, DBR/DP analyser coverage). The
  runner sanitises filenames before docker-cp'ing them in, so the usual
  cartridge-dump filenames with parens / spaces work without quoting
  gymnastics. Output goes under `.local-test/` (gitignored); no ROM
  blobs leave the user's machine.
- `tests/PrintRealRomSnapshot.java` -- a richer headless post-script
  than `PrintSnesArtifacts.java`. In addition to the structural
  markers, it counts hardware-register symbols, distinct
  DBR-overridden instruction sites, distinct DP-overridden instruction
  sites, and dumps the first four instructions of the reset routine.
  This is what the smoke runner uses; it is not invoked by the GitHub
  Actions CI workflow.

### Verified end-to-end on the corpus

11 / 11 cartridges import without error and produce a usable Ghidra
program. Highlights:

- Final Fantasy III (FF6 USA, 3 MiB HiROM): 534 functions, 29 190
  instruction sites with the DBR/DP analyser propagating a non-default
  bank or direct page (the analyser is doing real work on this one).
- Star Fox (1 MiB LoROM, GSU): 248 functions, 494 DBR overrides, 221
  hardware-register labels (the extra 13 are the GSU register window
  at `$00:3030-$00:303F`).
- Super Mario RPG (4 MiB SA-1) and Star Ocean (6 MiB SPC7110) both go
  from "No load spec found" / `AddressOutOfBoundsException` in 1.2.0
  to importing cleanly.

## [1.2.0] — 2026-04-25

### Added

- Full bank-mirror visibility for LowRAM and the hardware-register
  window. The SNES bus mirrors `$7E:0000-$1FFF` and `$2000-$5FFF` into
  every bank in `$00-$3F` and `$80-$BF`; the loader now creates a
  byte-mapped block for each of those banks
  (`lowram_mirror_BB`, `hwregs_mirror_BB`). Without this, code that ran
  with `DBR=$30` (typical after `PHK ; PLB`) saw a bare 24-bit address
  for `LDA $0080` or `STA $2100` even though the DBR/DP analyser had
  resolved the bank correctly.
- New loader option **Mirror hardware-register labels into all banks
  $00-$3F and $80-$BF** (`-snesMirrorHwLabels`, default on). The
  decompiler keys symbol lookup on the absolute address, not the
  byte-mapped source, so mirroring the labels lets `STA $4200` from a
  PHK/PLB function in bank `$80` decompile as `NMITIMEN = ...` instead
  of `*(byte*)0x804200 = ...`. Adds ~25 K cheap labels on a typical
  cartridge.
- Per-vector context overrides in `SnesVectors`: native vectors now
  have `ctx_EF=ctx_MF=ctx_XF=0` set at their entry point (16-bit
  accumulator and indices), and emulation vectors stay at `=1`. SNES
  native NMI/IRQ handlers therefore decompile in 16-bit mode out of
  the box, without the analyst having to right-click → *Set register
  values* on every cartridge.
- GitHub Actions workflow `build-extension.yml` that downloads a Ghidra
  release, builds the extension zip, uploads it as a CI artifact, and
  attaches it to a GitHub release when the workflow runs on a release
  event.
- **Three-ROM behavioural smoke suite** in the build workflow.
  Each CI run synthesizes its inputs from `tests/*.py` (no committed
  ROM blobs), imports them via `analyzeHeadless`, and asserts via
  `tests/PrintSnesArtifacts.java` that the loader produced the
  required artefacts. Failure uploads the headless log, the
  marker file, and the synthesised ROM as a CI artefact.
  - `synth-min-lorom.py` — baseline LoROM mapping. Asserts language
    ID, map-mode byte at `$00:FFD5`, every native + emulation vector
    label, the bank-mirror blocks (`lowram_mirror_01`,
    `hwregs_mirror_3F`, ...), the mirrored `NMITIMEN`
    hardware-register labels (`@ $00:4200`, `$01:4200`,
    `$3F:4200`), the `Reset` function entry point, and the
    per-vector `ctx_EF=ctx_MF=ctx_XF=1` override at `$00:8000`.
  - `synth-idiom-lorom.py` — a LoROM whose RESET stub exercises
    `LDA #$80; PHA; PLB` and `LDA #$1234; TCD`. Asserts that
    `SnesContextAnalyzer` propagated `DBR=$80` to the instruction
    immediately following `PLB` and `DP=$1234` to the instruction
    immediately following `TCD`. A regression in the analyser is
    therefore a build failure, not a silent quality drop on user
    ROMs.
  - `synth-min-hirom.py` — a HiROM stub. Asserts `mapMode=$21` at
    `$00:FFD5`, the HiROM bank-`$C0` primary block, and the
    `$00:8000` and `$80:8000` upper-half mirrors that
    `HiRomLoader` lays down. This is the first time the HiROM
    code path has had CI coverage; previously only LoROM was
    exercised.
- Cross-platform build matrix: the workflow now builds on
  `ubuntu-latest` *and* `windows-latest`, so packaging issues
  specific to Git-Bash, the `sleigh.bat` launcher, or Gradle's
  Windows shims surface in CI rather than at user install time.
  Smoke tests run on Linux to keep matrix runtime bounded.

### Changed

- `mapHwRegs` now describes the block as `$00:2000-$00:43FF`
  (previously the comment said `$00:2100`, off-by-`$100`).

## [1.1.0] — 2026-04-25

### Added

- **DBR / DP tracking analyser** (`SnesContextAnalyzer`) bundled with the
  extension. Recognises the most common 65816 idioms for switching the
  Data Bank Register and Direct Page register and propagates the resulting
  values into Ghidra's program context so absolute / direct-page addresses
  resolve correctly in the decompiler:
  - `PHK ; PLB`                  → `DBR := PBR`
  - `LDA #imm8 ; PHA ; PLB`      → `DBR := imm`
  - `PEA #imm16 ; PLB ; PLB`     → `DBR := imm.high`
  - `LDA #imm16 ; TCD`           → `DP  := imm`
  - `LDA #imm16 ; PHA ; PLD`     → `DP  := imm`
  - `PEA #imm16 ; PLD`           → `DP  := imm`
- Coprocessor / cartridge add-on detection: SA-1, SuperFX (GSU-1/2),
  S-DD1, OBC-1, S-RTC, Cx4, SPC7110, ST010/011/018, plus the older DSP
  family. Surfaced through `SnesHeader.getCoprocessor()` and the cartridge
  description in the loader log.
- ExHiROM detection and labelling (`mapMode == 0x25 / 0x35`).
- Named MSU-1 / SD2SNES streaming registers at `$00:2000-$00:2007`
  (`MSU_STATUS`, `MSU_READ`, `MSU_AUDIO_CONTROL`, …).
- Named SA-1 register window at `$00:2200-$00:222A`
  (`SA1_CCNT`, `SA1_SIE`, `SA1_CXB-FXB`, BW-RAM control, …).
- Named SuperFX (GSU) register window at `$00:3030-$00:303F`
  (`GSU_SFR`, `GSU_PBR`, `GSU_SCMR`, …).
- Named S-DD1 register window at `$00:4800-$00:4807`
  (`SDD1_DMA_TRIGGER`, `SDD1_MMC0-3`, …).
- Plate comment at the reset entry point summarising the decoded
  cartridge header (title, map mode, cart type, region, version,
  reset vector, checksum).

### Changed

- The hardware-register memory block now starts at `$00:2000` instead of
  `$00:2100` so the MSU-1 window is covered by a single block.
- Loader description in `extension.properties` rewritten to reflect the
  new capabilities.
- `SnesHeader.describe()` now also reports the cartridge type and
  coprocessor family.

### Build / docs

- README rewritten to describe the analyser, the new symbolisation, the
  loader option flags, and the install order alongside `ghidra-65816`.

## [1.0.0] — 2026-04-25

Initial standalone release of the modernised fork. Brings the
[`achan1989/ghidra-snes-loader`](https://github.com/achan1989/ghidra-snes-loader)
extension forward to current Ghidra (12.x), drops the unmaintained warning,
and documents the dependency on the companion `ghidra-65816` processor module.

### Added

- LoROM and HiROM detection with and without an SMC copier header.
- `SnesPostLoader` lays down WRAM, the LowRAM mirror, the hardware-register
  window, cartridge SRAM (when the header advertises one), the
  cartridge-header data type, and the native + emulation interrupt vector
  tables.
- `SnesHardware` exhaustively names the PPU/CPU/APU/DMA hardware-register
  set and turns each into a labelled byte with an EOL comment.
- `SnesVectors` resolves every interrupt vector in bank `$00` and creates
  a function at each target, marking the reset vector as the program's
  external entry point.

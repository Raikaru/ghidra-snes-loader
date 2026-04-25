# Changelog

All notable changes to this loader extension are documented here. The
versioning follows [SemVer](https://semver.org/) for the extension's
`extension.properties`.

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
- Smoke-test step in the build workflow. Synthesizes a 128 KiB LoROM
  via `tests/synth-min-lorom.py`, runs `analyzeHeadless` against it
  with the freshly-built extension and the
  [`ghidra-65816`](https://github.com/Raikaru/ghidra-65816) processor
  module, then asserts via `tests/PrintSnesArtifacts.java` that the
  expected vector labels (`vector_RESET`, `vector_NMI_native`, ...),
  the bank-mirror blocks (`lowram_mirror_01`, `hwregs_mirror_3F`,
  ...), the mirrored hardware-register labels
  (`NMITIMEN @ $00:4200`, `$01:4200`, `$3F:4200`), and the `Reset`
  function entry point are all present. A regression in any of those
  features now fails CI and uploads the headless log + ROM image as a
  failure artefact for offline diagnosis.

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

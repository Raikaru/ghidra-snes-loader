# ghidra-snes-loader

SNES ROM loader extension for Ghidra (LoROM/HiROM detection, header decoding,
memory map creation, and vector labeling).

This repo is the **loader half** of the setup. It depends on the companion
65816 processor module:
- `ghidra-65816` (language ID `65816:LE:16:default`)

## What it does

- Detects SNES ROM images (including optional SMC copier headers)
- Selects the 65816 language/compiler pair for import
- Creates SNES-relevant memory blocks (WRAM/register windows/SRAM)
- Applies cartridge header structures and names interrupt vectors
- Sets Reset/vector entry points to improve initial analysis

## Build

Build with Gradle and `GHIDRA_INSTALL_DIR` set to your local Ghidra path.

Linux:
1. `cd SnesLoader`
2. `GHIDRA_INSTALL_DIR='/abs/path/to/ghidra' ./gradlew buildExtension`

Windows:
1. `cd SnesLoader`
2. `set GHIDRA_INSTALL_DIR=C:\abs\path\to\ghidra && gradlew.bat buildExtension`

The output extension zip is produced under `SnesLoader/dist`.

## Install order

1. Install `ghidra-65816` into `Ghidra/Processors/65816`
2. Compile `65816.slaspec` to `65816.sla` (via Ghidra `support/sleigh`)
3. Install this extension zip into Ghidra extensions

Without step 1, loader imports will fail to bind a valid 65816 language.

## Provenance

Originally based on `achan1989/ghidra-snes-loader` (archived upstream), with
updates for modern Ghidra compatibility and tighter integration with the
revised 65816 processor module.

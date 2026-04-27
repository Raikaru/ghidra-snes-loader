# SMT-Family Validation Seeds

Use this as a local checklist when SMT1, SMT2, or SMT if... are used as
real-ROM validation targets for the Ghidra stack. These are questions to answer
with payload-free notes, not decomp artifacts to commit.

## Loader Basics

- Does import select `65816:LE:16:default`?
- Is the ROM kind classified correctly?
- Are reset, NMI, IRQ, BRK, COP, and abort vectors labeled?
- Is the reset target made into a function?
- Are ROM, WRAM, LowRAM mirror, hardware register, and SRAM blocks sane?
- Are primary and mirrored hardware labels present?

## Decompiler Usefulness

- Do reset/init routines decompile with direct calls instead of opaque indirect flow?
- Does `SNES Function Discovery` increase direct-call function count without obvious false positives?
- Are `candidate_indirect_*` labels plausible dispatchers or jump-table sites?
- Do common `PHK/PLB`, `PHA/PLB`, `PEA/PLB`, `TCD`, and `PLD` idioms improve DBR/DP context?
- Do absolute/direct-page memory references resolve into the intended banks?
- Do function boundaries around dispatchers need loader/analyzer improvements?

## Port-Relevant Areas

- reset/init flow;
- controller read path;
- menu dispatcher;
- text pointer lookup;
- map/room transition dispatcher;
- event/script dispatch boundary;
- battle entry and table access;
- SPC upload routines;
- sound command writes to APU ports.

## What To Record

Record:

- label;
- bus address;
- file offset if known;
- function name/address;
- hypothesis;
- structural evidence;
- needed synthetic regression or loader/analyzer improvement.

Do not record copied code, decoded text, graphics, screenshots, audio, maps,
scripts, samples, saves, or raw bytes.

## Current Private-ROM Baseline

When run locally with the private SMT2 and SMT if... ROMs, the stack should at
minimum:

- import with `65816:LE:16:default`;
- report map mode `20` for LoROM;
- create vector symbols;
- create hardware-register symbols;
- create functions from direct call targets;
- report indirect-flow candidates for manual dispatcher/jump-table review;
- produce non-zero DBR/DP analyzer coverage;
- report APU-port reference candidates when the game touches `$2140-$2143`;
- write only ignored `.local-test/structure-export/*.json` summaries.

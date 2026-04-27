# Decomp Readiness Workflow

This stack is useful for decomp work when the first Ghidra import gives enough
structure to start naming systems instead of hand-carving every entry point.

## Pass Order

1. Run the synthetic stack smoke.
2. Run `export-structure-batch.ps1` over private validation ROMs.
3. Compare function, direct-call target, indirect-flow, DBR/DP,
   hardware-reference, and APU-reference counts against the previous local run.
4. Open the Ghidra project and inspect a sample of new `sub_*` functions.
5. Inspect `candidate_indirect_*` labels as possible dispatchers or jump-table
   readers.
6. Use `export-apu-candidates.ps1` to locate 65816-side sound/APU handoff code.
7. Analyze extracted or emulator-observed SPC700 blobs separately with
   `ghidra-spc700`.

## What Good Looks Like

- Vector targets exist and have functions.
- Direct `JSR`/`JSL` targets become functions.
- Computed flow is labeled for review instead of guessed through.
- DBR/DP coverage is non-zero in real code.
- Hardware-register and APU-port references are counted as structural leads.
- Local validation outputs stay under `.local-test/` and contain no ROM bytes,
  decoded text, copied disassembly, graphics, screenshots, audio, maps, scripts,
  samples, saves, or raw byte ranges.

## When To Add Synthetic Tests

Add a synthetic ROM test when a real game reveals a reusable loader or analyzer
bug, such as:

- a direct call form that should create a function;
- a DBR/DP idiom that should propagate context;
- a hardware/APU reference that should resolve symbolically;
- a safe jump-table pattern that can be recognized without game payload.

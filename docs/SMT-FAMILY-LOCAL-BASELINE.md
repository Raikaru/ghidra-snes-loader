# SMT-Family Local Baseline

These are payload-free baseline signals from private local SMT-family ROMs.
They are counts and structural metadata only; they are not committed fixtures
and do not include ROM bytes, decoded text, copied disassembly, graphics,
screenshots, audio, maps, scripts, samples, saves, or raw byte ranges.

Current expected local signals:

| ROM | Functions | Direct-call targets with functions | Indirect candidates | Hardware refs | APU refs | DBR refs | DP refs |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SMT2 | 76 | 69 | 0 | 20 | 0 | 1154 | 140 |
| SMT if... | 43 | 37 | 0 | 32 | 0 | 688 | 140 |

Interpretation:

- Direct-call target counts confirm that the current import has callable
  structure beyond vector functions.
- Zero indirect candidates means the first-pass analyzer did not find safe
  computed-flow sites to label from the current decoded set; dispatchers may
  still need manual navigation or a later game-informed script.
- Zero APU-port references means `$2140-$2143` handoff code is not surfaced by
  the initial decoded function set yet. Use emulator traces, manual labels, or
  future data-flow work to seed those paths before SPC700 extraction.

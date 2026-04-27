# SMT-Family Local Baseline

These are payload-free baseline signals from private local SMT-family ROMs.
They are counts and structural metadata only; they are not committed fixtures
and do not include ROM bytes, decoded text, copied disassembly, graphics,
screenshots, audio, maps, scripts, samples, saves, or raw byte ranges.

Current expected local signals:

| ROM | Functions | Direct-call targets with functions | Indirect candidates | Hardware refs | APU refs | APU scalar candidates | DBR refs | DP refs | Analyzer errors |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| SMT2 | 76 | 69 | 0 | 34 | 0 | 37 | 1154 | 140 | 2 |
| SMT if... | 43 | 37 | 0 | 30 | 0 | 40 | 688 | 140 | 2 |

Interpretation:

- Direct-call target counts confirm that the current import has callable
  structure beyond vector functions.
- Zero indirect candidates means the first-pass analyzer did not find safe
  computed-flow sites to label from the current decoded set; dispatchers may
  still need manual navigation or a later game-informed script.
- Zero APU-port references means `$2140-$2143` handoff code is not surfaced by
  resolved references in the initial decoded function set yet. Scalar
  candidates are broader and may include setup code, address operands, or other
  values that have not resolved to hardware labels.
- Analyzer errors are local headless-log diagnostics. They are not payload and
  should be reduced with synthetic tests before changing shared processor or
  loader behavior.
- Pointer-table candidate exports are intentionally tied to nearby indirect
  flow. If no indirect-flow sites are decoded yet, zero table candidates is a
  useful signal that more function/data discovery is needed first.

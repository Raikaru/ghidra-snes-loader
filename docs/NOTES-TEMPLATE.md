# Validation Notes Template

Use this for local reverse-engineering or real-ROM validation notes. Keep notes payload-free.

```text
title:
date:
tool versions:
  ghidra:
  ghidra-65816:
  ghidra-snes-loader:
  ghidra-spc700:

rom identity:
  filename:
  sha256:
  size:
  local-only: yes

observation:
  surface:
  bus address:
  file offset:
  label:
  function:
  hypothesis:

evidence:
  source:
  markers/logs:
  related symbols:
  related memory blocks:
  dbr/dp context:

payload safety:
  contains_rom_bytes: no
  contains_decoded_text: no
  contains_assets_or_screenshots: no

next validation:
```

Good notes name addresses, labels, structure shapes, and hypotheses. Bad notes copy data payloads.

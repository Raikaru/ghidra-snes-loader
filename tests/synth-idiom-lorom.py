#!/usr/bin/env python3
"""Synthesize a 128 KiB LoROM whose RESET stub exercises the DBR/DP idioms
the SNES loader's context analyser is supposed to recognise.

Stub layout at $00:8000 (file offset 0):

    78           SEI
    18           CLC
    FB           XCE              -> native mode (E := 0)
    E2 30        SEP #$30         -> m=x=1 (8-bit A,X,Y)
    A9 80        LDA #$80         (8-bit immediate)
    48           PHA
    AB           PLB              -> DBR := $80    (analyser test #1)
    AD 34 12     LDA $1234        ; <- DBR is expected to be $80 here
    C2 20        REP #$20         -> m=0 (16-bit A)
    A9 34 12     LDA #$1234       (16-bit immediate)
    5B           TCD              -> DP  := $1234  (analyser test #2)
    AD 78 56     LDA $5678        ; <- DP is expected to be $1234 here
    DB           STP

Test points the CI asserter cares about:
    $00:8009  DBR == 0x80
    $00:8012  DP  == 0x1234

The header, vectors, checksum, and surrounding zero-fill are otherwise
identical to ``synth-min-lorom.py``. We deliberately keep the two files
side-by-side rather than parameterising a single script: the smoke tests
they feed are read by humans, and ``diff`` between them is the cheapest
way to see exactly what changed in the stub.
"""
from __future__ import annotations

import struct
import sys


ROM_SIZE = 0x20000
HEADER_OFF = 0x7FC0
NATIVE_VEC_OFF = 0x7FE0
EMU_VEC_OFF = 0x7FF0


# Reset stub bytes. Indexed comments document the one-byte operands so
# the asserter's hard-coded test-point addresses stay in sync with the
# actual instruction layout.
STUB = bytes([
    0x78,                    # 8000  SEI
    0x18,                    # 8001  CLC
    0xFB,                    # 8002  XCE
    0xE2, 0x30,              # 8003  SEP #$30
    0xA9, 0x80,              # 8005  LDA #$80
    0x48,                    # 8007  PHA
    0xAB,                    # 8008  PLB         ; DBR := $80
    0xAD, 0x34, 0x12,        # 8009  LDA $1234   <- DBR test point
    0xC2, 0x20,              # 800C  REP #$20
    0xA9, 0x34, 0x12,        # 800E  LDA #$1234
    0x5B,                    # 8011  TCD         ; DP := $1234
    0xAD, 0x78, 0x56,        # 8012  LDA $5678   <- DP test point
    0xDB,                    # 8015  STP
])


def build() -> bytes:
    rom = bytearray(b"\xFF" * ROM_SIZE)
    rom[0:len(STUB)] = STUB

    title = b"GHIDRA SNES LDR IDIOMS".ljust(21, b" ")[:21]
    rom[HEADER_OFF:HEADER_OFF + 21] = title
    rom[HEADER_OFF + 0x15] = 0x20  # mapMode: LoROM, slow
    rom[HEADER_OFF + 0x16] = 0x00  # cartridgeType
    rom[HEADER_OFF + 0x17] = 0x07  # romSize: 128 KiB
    rom[HEADER_OFF + 0x18] = 0x00  # ramSize
    rom[HEADER_OFF + 0x19] = 0x01  # region
    rom[HEADER_OFF + 0x1A] = 0x00  # devId
    rom[HEADER_OFF + 0x1B] = 0x00  # version

    def put_vec(off: int, addr: int) -> None:
        rom[off:off + 2] = struct.pack("<H", addr & 0xFFFF)

    for i in range(0, 16, 2):
        put_vec(NATIVE_VEC_OFF + i, 0xFFFF)
    for i in range(0, 16, 2):
        put_vec(EMU_VEC_OFF + i, 0xFFFF)
    put_vec(EMU_VEC_OFF + 0x0C, 0x8000)  # RESET

    rom[HEADER_OFF + 0x1C] = 0xFF
    rom[HEADER_OFF + 0x1D] = 0xFF
    rom[HEADER_OFF + 0x1E] = 0x00
    rom[HEADER_OFF + 0x1F] = 0x00
    raw = sum(rom) & 0xFFFF
    checksum = raw
    complement = checksum ^ 0xFFFF
    rom[HEADER_OFF + 0x1C:HEADER_OFF + 0x1E] = struct.pack("<H", complement)
    rom[HEADER_OFF + 0x1E:HEADER_OFF + 0x20] = struct.pack("<H", checksum)
    return bytes(rom)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: synth-idiom-lorom.py <output.smc>", file=sys.stderr)
        return 2
    with open(argv[1], "wb") as fh:
        fh.write(build())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

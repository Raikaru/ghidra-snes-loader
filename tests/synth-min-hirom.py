#!/usr/bin/env python3
"""Synthesize a minimal valid 128 KiB SNES HiROM for the loader smoke test.

HiROM mapping puts the cartridge header at file offset ``$FFC0`` and maps
the first 64 KiB of the file at bank ``$C0:0000`` (and the upper half
``$C0:8000-$C0:FFFF`` mirrors at ``$00:8000-$00:FFFF``). The CPU still
boots from ``$00:FFFC``, which on this layout reads from file offset
``$FFFC`` -- i.e. the very last word of the first 64 KiB chunk.

We park the RESET stub at file offset ``$8000`` so it is reachable as
both ``$C0:8000`` and ``$00:8000``. The stub itself is the same minimal
``SEI; CLC; XCE; SEP #$30; STP`` as the LoROM smoke ROM, so the
HiROM-specific test only validates the *mapping*: that bank ``C0`` and
its mirrors actually appear in the program after import.

Usage:
    python3 synth-min-hirom.py <output.smc>
"""
from __future__ import annotations

import struct
import sys


ROM_SIZE = 0x20000
HEADER_OFF = 0xFFC0  # HiROM header location
NATIVE_VEC_OFF = 0xFFE0
EMU_VEC_OFF = 0xFFF0
STUB_OFF = 0x8000


def build() -> bytes:
    rom = bytearray(b"\xFF" * ROM_SIZE)

    stub = bytes([0x78, 0x18, 0xFB, 0xE2, 0x30, 0xDB])
    rom[STUB_OFF:STUB_OFF + len(stub)] = stub

    title = b"GHIDRA SNES HIROM TEST".ljust(21, b" ")[:21]
    rom[HEADER_OFF:HEADER_OFF + 21] = title
    rom[HEADER_OFF + 0x15] = 0x21  # mapMode: HiROM, slow
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
        print("usage: synth-min-hirom.py <output.smc>", file=sys.stderr)
        return 2
    with open(argv[1], "wb") as fh:
        fh.write(build())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

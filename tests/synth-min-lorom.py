#!/usr/bin/env python3
"""Synthesize a minimal valid 128 KiB SNES LoROM for the loader smoke test.

The result is a 128 KiB ROM image (no SMC copier header) that satisfies
SnesLoader's LoROM heuristic:

  * Title field is 21 ASCII bytes at $7FC0
  * Map mode 0x20 (LoROM, slow)
  * Cart type 0x00 (ROM only)
  * ROM size code 0x07 (128 KiB == 2^7 * 1 KiB) -- the smallest size the
    loader's getRomBytes() heuristic considers valid; using a smaller
    size makes the loader log a 0 KiB ROM and is annoying for diagnostics.
  * RAM size 0x00 (no SRAM)
  * Region 0x01 (NTSC USA)
  * Native + emulation vectors filled in
  * Header checksum / complement pair correctly computed for the whole image

The RESET vector ($00FFFC) points at $8000, where we write a tiny stub:

    SEI; CLC; XCE; SEP #$30; STP

so the disassembler has something concrete to chew on.

Usage:
    python3 synth-min-lorom.py <output_path>

This script intentionally has no third-party dependencies; it is meant to be
trivially callable from a GitHub Actions step.
"""
from __future__ import annotations

import os
import struct
import sys


ROM_SIZE = 0x20000  # 128 KiB
HEADER_OFF = 0x7FC0
NATIVE_VEC_OFF = 0x7FE0
EMU_VEC_OFF = 0x7FF0


def build() -> bytes:
    rom = bytearray(b"\xFF" * ROM_SIZE)

    # Reset stub at $8000 (== file offset 0).
    # SEI = 0x78, CLC = 0x18, XCE = 0xFB, SEP #$30 = 0xE2 0x30, STP = 0xDB.
    stub = bytes([0x78, 0x18, 0xFB, 0xE2, 0x30, 0xDB])
    rom[0:len(stub)] = stub

    title = b"GHIDRA SNES LDR TEST".ljust(21, b" ")
    rom[HEADER_OFF:HEADER_OFF + 21] = title
    rom[HEADER_OFF + 0x15] = 0x20  # mapMode: LoROM, slow
    rom[HEADER_OFF + 0x16] = 0x00  # cartridgeType: ROM only
    rom[HEADER_OFF + 0x17] = 0x07  # romSize: 128 KiB
    rom[HEADER_OFF + 0x18] = 0x00  # ramSize: none
    rom[HEADER_OFF + 0x19] = 0x01  # region: NTSC USA
    rom[HEADER_OFF + 0x1A] = 0x00  # devId
    rom[HEADER_OFF + 0x1B] = 0x00  # version
    # Header checksum + complement at $7FDC..$7FDF are written below.

    def put_vec(off: int, addr: int) -> None:
        rom[off:off + 2] = struct.pack("<H", addr & 0xFFFF)

    # Native vectors (00FFE0-00FFEF) -- unused entries point to $FFFF.
    for i in range(0, 16, 2):
        put_vec(NATIVE_VEC_OFF + i, 0xFFFF)

    # Emulation vectors (00FFF0-00FFFF) -- only RESET is meaningful.
    for i in range(0, 16, 2):
        put_vec(EMU_VEC_OFF + i, 0xFFFF)
    put_vec(EMU_VEC_OFF + 0x0C, 0x8000)  # RESET vector

    # SNES checksum is the 16-bit unsigned sum of every byte in the ROM,
    # *with the checksum and complement themselves treated as $00 / $FF*.
    # The complement is the bitwise inverse of the checksum.
    rom[HEADER_OFF + 0x1C] = 0xFF  # complement low (placeholder)
    rom[HEADER_OFF + 0x1D] = 0xFF  # complement high (placeholder)
    rom[HEADER_OFF + 0x1E] = 0x00  # checksum low (placeholder)
    rom[HEADER_OFF + 0x1F] = 0x00  # checksum high (placeholder)
    raw = sum(rom) & 0xFFFF
    checksum = raw
    complement = checksum ^ 0xFFFF
    rom[HEADER_OFF + 0x1C:HEADER_OFF + 0x1E] = struct.pack("<H", complement)
    rom[HEADER_OFF + 0x1E:HEADER_OFF + 0x20] = struct.pack("<H", checksum)
    return bytes(rom)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: synth-min-lorom.py <output.smc>", file=sys.stderr)
        return 2
    out = argv[1]
    data = build()
    with open(out, "wb") as fh:
        fh.write(data)
    print(f"Wrote {len(data)} bytes to {out}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

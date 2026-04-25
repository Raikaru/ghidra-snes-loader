// SPDX-License-Identifier: MIT
package snesloader;

import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.app.util.bin.ByteProvider;

/**
 * Decoded SNES "internal ROM header" at offset $FFC0 (HiROM) or $7FC0 (LoROM)
 * inside the ROM image (after stripping any optional 512-byte SMC copier header).
 *
 * Layout (relative to the header start):
 * <pre>
 *   +0x00  21 bytes  Title (ASCII, space padded)
 *   +0x15   1 byte   Map mode (e.g. 0x20 LoROM, 0x21 HiROM, 0x25 ExHiROM, 0x30 LoROM+FastROM, ...)
 *   +0x16   1 byte   Cartridge type (ROM, ROM+RAM, ROM+RAM+SRAM, ...)
 *   +0x17   1 byte   ROM size (1 KiB << n)
 *   +0x18   1 byte   RAM/SRAM size (1 KiB << n, 0 = none)
 *   +0x19   1 byte   Region (Japan / NA / EU / ...)
 *   +0x1A   1 byte   Developer ID (0x33 = extended header present at +0x00..0x0F)
 *   +0x1B   1 byte   ROM version
 *   +0x1C   2 bytes  Checksum complement (LE)
 *   +0x1E   2 bytes  Checksum (LE; checksum + complement == 0xFFFF when valid)
 *   +0x20   4 bytes  unused (sometimes used by extended header)
 *   +0x24   2 bytes  Native COP vector
 *   +0x26   2 bytes  Native BRK vector
 *   +0x28   2 bytes  Native ABORT vector
 *   +0x2A   2 bytes  Native NMI vector
 *   +0x2C   2 bytes  reserved
 *   +0x2E   2 bytes  Native IRQ vector
 *   +0x34   2 bytes  Emulation COP vector
 *   +0x36   2 bytes  reserved
 *   +0x38   2 bytes  Emulation ABORT vector
 *   +0x3A   2 bytes  Emulation NMI vector
 *   +0x3C   2 bytes  Emulation RESET vector
 *   +0x3E   2 bytes  Emulation IRQ/BRK vector
 * </pre>
 */
public final class SnesHeader {

	public static final int SNES_HEADER_LEN = 64;

	public static final int TITLE_OFFSET = 0x00;
	public static final int TITLE_LEN = 21;
	public static final int MAP_MODE_OFFSET = 0x15;
	public static final int CARTRIDGE_TYPE_OFFSET = 0x16;
	public static final int ROM_SIZE_OFFSET = 0x17;
	public static final int RAM_SIZE_OFFSET = 0x18;
	public static final int REGION_OFFSET = 0x19;
	public static final int DEV_ID_OFFSET = 0x1A;
	public static final int VERSION_OFFSET = 0x1B;
	public static final int COMPLEMENT_OFFSET = 0x1C;
	public static final int CHECKSUM_OFFSET = 0x1E;

	public static final int NATIVE_VECTORS_OFFSET = 0x24; // 6 vectors over 12 bytes
	public static final int EMULATION_VECTORS_OFFSET = 0x34; // 6 vectors over 12 bytes
	public static final int VECTOR_RESET = 0x3C; // emulation RESET vector

	private final byte[] raw;
	private final String title;
	private final int mapMode;
	private final int cartridgeType;
	private final int romSize;
	private final int ramSize;
	private final int region;
	private final int devId;
	private final int version;
	private final int complement;
	private final int checksum;

	private SnesHeader(byte[] raw) {
		this.raw = raw;
		ByteBuffer b = ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN);

		StringBuilder sb = new StringBuilder(TITLE_LEN);
		for (int i = 0; i < TITLE_LEN; i++) {
			int c = raw[TITLE_OFFSET + i] & 0xFF;
			sb.append((c >= 0x20 && c <= 0x7E) ? (char) c : ' ');
		}
		this.title = sb.toString().trim();
		this.mapMode = raw[MAP_MODE_OFFSET] & 0xFF;
		this.cartridgeType = raw[CARTRIDGE_TYPE_OFFSET] & 0xFF;
		this.romSize = raw[ROM_SIZE_OFFSET] & 0xFF;
		this.ramSize = raw[RAM_SIZE_OFFSET] & 0xFF;
		this.region = raw[REGION_OFFSET] & 0xFF;
		this.devId = raw[DEV_ID_OFFSET] & 0xFF;
		this.version = raw[VERSION_OFFSET] & 0xFF;
		this.complement = b.getShort(COMPLEMENT_OFFSET) & 0xFFFF;
		this.checksum = b.getShort(CHECKSUM_OFFSET) & 0xFFFF;
	}

	public static SnesHeader fromProviderAtOffset(ByteProvider provider, long offset)
			throws IOException {
		if (offset < 0) {
			throw new IllegalArgumentException("offset cannot be negative");
		}
		if (offset + SNES_HEADER_LEN > provider.length()) {
			throw new IOException("Header offset past end of file: 0x" + Long.toHexString(offset));
		}
		return new SnesHeader(provider.readBytes(offset, SNES_HEADER_LEN));
	}

	/**
	 * Heuristic: do these bytes plausibly form a SNES header? We require a sane
	 * map mode, a checksum that complements correctly and a reset vector that
	 * lives in the bank-bus ROM range ($8000+).
	 */
	public boolean looksValid() {
		int mapHi = (mapMode >> 4) & 0x0F;
		int mapLo = mapMode & 0x0F;
		boolean validMap = (mapHi == 2 || mapHi == 3) // 2x = LoROM-ish, 3x = FastROM
				&& (mapLo == 0 || mapLo == 1 || mapLo == 2 || mapLo == 5);
		boolean validCk = ((checksum + complement) & 0xFFFF) == 0xFFFF;
		int reset = getResetVector();
		boolean validReset = Integer.compareUnsigned(reset, 0x8000) >= 0;
		return validMap && validCk && validReset;
	}

	/** Read a 16-bit little-endian word out of the raw header. */
	public int word(int offset) {
		return ByteBuffer.wrap(raw).order(ByteOrder.LITTLE_ENDIAN).getShort(offset) & 0xFFFF;
	}

	public byte[] raw() { return raw; }
	public String getTitle() { return title; }
	public int getMapMode() { return mapMode; }
	public int getCartridgeType() { return cartridgeType; }
	public int getRomSizeCode() { return romSize; }
	public int getRamSizeCode() { return ramSize; }
	public int getRegion() { return region; }
	public int getDevId() { return devId; }
	public int getVersion() { return version; }
	public int getComplement() { return complement; }
	public int getChecksum() { return checksum; }

	/** Emulation RESET vector (16-bit, executes in bank $00). */
	public int getResetVector() {
		return word(VECTOR_RESET);
	}

	/** Header-claimed ROM size in bytes; 0 if the field is invalid. */
	public int getRomBytes() {
		if (romSize < 7 || romSize > 0x10) {
			return 0;
		}
		return 1024 << romSize;
	}

	/** SRAM size in bytes (0 means none). */
	public int getSramBytes() {
		if (ramSize == 0 || ramSize > 0x09) {
			return 0;
		}
		return 1024 << ramSize;
	}

	public boolean isFastRom() {
		return ((mapMode >> 4) & 0x0F) == 3;
	}

	public boolean isHiRomMode() {
		int lo = mapMode & 0x0F;
		return lo == 1 || lo == 5; // 0x21/0x31 HiROM, 0x25/0x35 ExHiROM
	}

	public boolean isLoRomMode() {
		int lo = mapMode & 0x0F;
		return lo == 0 || lo == 2; // 0x20/0x30 LoROM, 0x22/0x32 LoROM SA-1, etc.
	}

	public String describeRegion() {
		switch (region) {
			case 0x00: return "Japan (NTSC)";
			case 0x01: return "North America (NTSC)";
			case 0x02: return "Europe/Australia (PAL)";
			case 0x03: return "Sweden/Scandinavia (PAL)";
			case 0x04: return "Finland (PAL)";
			case 0x05: return "Denmark (PAL)";
			case 0x06: return "France (PAL)";
			case 0x07: return "Netherlands (PAL)";
			case 0x08: return "Spain (PAL)";
			case 0x09: return "Germany/Austria/Switzerland (PAL)";
			case 0x0A: return "Italy (PAL)";
			case 0x0B: return "Hong Kong/China (PAL)";
			case 0x0C: return "Indonesia (PAL)";
			case 0x0D: return "South Korea (NTSC)";
			default:   return String.format("Unknown ($%02X)", region);
		}
	}

	public String describeMapMode() {
		StringBuilder sb = new StringBuilder();
		if (isLoRomMode()) sb.append("LoROM");
		else if (isHiRomMode()) sb.append("HiROM");
		else sb.append("Unknown");
		if (isFastRom()) sb.append(", FastROM");
		sb.append(String.format(" (mapMode=$%02X)", mapMode));
		return sb.toString();
	}

	public String describe() {
		return String.format(
			"title='%s' mapMode=%s romSizeCode=$%02X (%dKB) sramCode=$%02X (%dKB) " +
			"region=%s version=$%02X resetVec=$%04X checksum=$%04X complement=$%04X",
			title, describeMapMode(), romSize, getRomBytes() / 1024,
			ramSize, getSramBytes() / 1024,
			describeRegion(), version, getResetVector(), checksum, complement);
	}
}

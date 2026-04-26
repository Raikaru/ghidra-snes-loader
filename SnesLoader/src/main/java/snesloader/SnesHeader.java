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
	 *
	 * <p>Recognised low-nibble values:
	 * <ul>
	 *   <li>0 = LoROM ($20/$30)</li>
	 *   <li>1 = HiROM ($21/$31)</li>
	 *   <li>2 = LoROM SDD-1 / extended LoROM ($22/$32)</li>
	 *   <li>3 = LoROM SA-1 ($23/$33) -- previously dropped, which made every
	 *       SA-1 cartridge (Super Mario RPG, Kirby Super Star, Kirby's Dream
	 *       Land 3, Mario's Super Picross, ...) fall through to "No load
	 *       spec found".</li>
	 *   <li>5 = HiROM ExHiROM ($25/$35)</li>
	 *   <li>A = HiROM SPC7110 ($3A) -- ditto for Star Ocean and Far East of
	 *       Eden Zero.</li>
	 * </ul></p>
	 */
	public boolean looksValid() {
		int mapHi = (mapMode >> 4) & 0x0F;
		int mapLo = mapMode & 0x0F;
		boolean validMap = (mapHi == 2 || mapHi == 3) // 2x = LoROM-ish, 3x = FastROM
				&& (mapLo == 0 || mapLo == 1 || mapLo == 2 || mapLo == 3
					|| mapLo == 5 || mapLo == 0xA);
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
		// 0x21/0x31 HiROM, 0x25/0x35 ExHiROM/ExLoROM, 0x3A SPC7110.
		return lo == 1 || lo == 5 || lo == 0xA;
	}
	public boolean isExLoRomMode() {
		return (mapMode & 0x0F) == 5;
	}

	public boolean isExHiRomMode() {
		// nibble 5 is ExLoROM when loaded by LoRomLoader, ExHiROM when loaded by HiRomLoader.
		return (mapMode & 0x0F) == 5;
	}

	public boolean isLoRomMode() {
		int lo = mapMode & 0x0F;
		// 0x20/0x30 LoROM, 0x22/0x32 LoROM SDD-1, 0x23/0x33 LoROM SA-1, 0x25/0x35 ExLoROM.
		return lo == 0 || lo == 2 || lo == 3 || lo == 5;
	}

	/** True if this map-mode is the SPC7110-specific HiROM variant. */
	public boolean isSpc7110Mode() {
		return (mapMode & 0x0F) == 0xA;
	}

	/** True if this map-mode is the SA-1-specific LoROM variant. */
	public boolean isSa1Mode() {
		return (mapMode & 0x0F) == 0x3;
	}

	/**
	 * Coprocessor / cartridge add-on chip embedded on the cartridge, derived
	 * from the high nibble of the cartridge type when the low nibble indicates
	 * a non-trivial component (anything other than ROM-only).
	 *
	 * <p>References:
	 * <a href="https://snes.nesdev.org/wiki/ROM_header">SNESdev wiki — ROM header</a>.</p>
	 */
	public enum Coprocessor {
		NONE("None"),
		DSP1("DSP-1/2/3/4 (NEC uPD77C25)"),
		GSU("GSU/SuperFX"),
		OBC1("OBC-1"),
		SA1("SA-1"),
		SDD1("S-DD1"),
		SRTC("S-RTC"),
		OTHER("Other (Super Game Boy / SGB-1)"),
		CUSTOM_SPC7110("SPC7110 (Custom)"),
		CUSTOM_ST010_011("ST010/ST011 (Custom)"),
		CUSTOM_ST018("ST018 (Custom)"),
		CUSTOM_CX4("Cx4 (Custom)"),
		CUSTOM_UNKNOWN("Custom (unknown)");

		private final String description;
		Coprocessor(String description) { this.description = description; }
		public String describe() { return description; }
		public boolean isPresent() { return this != NONE; }
	}

	/**
	 * Decode the cartridge-type byte at $FFD6 into a {@link Coprocessor} value.
	 * Returns {@link Coprocessor#NONE} for plain ROM/RAM/SRAM cartridges.
	 *
	 * <p>The cart-type byte is laid out as ``hi:lo``. The low nibble names
	 * the components (ROM, ROM+RAM, ROM+RAM+battery, ROM+chip, ...). The
	 * high nibble names the coprocessor family <i>but only when the low
	 * nibble indicates that a chip is present (lo &gt;= 3)</i>.</p>
	 *
	 * <p>The high-nibble decoding here matches the SNESdev wiki's "ROM
	 * header" page: 0 = DSP, 1 = GSU/SuperFX, 2 = OBC1, 3 = SA-1, 4 = S-DD1,
	 * 5 = S-RTC, $E = Other (SGB-1), $F = Custom (sub-decoded by full byte).
	 * The original achan1989 loader was off by one here, which made every
	 * SuperFX cartridge (Star Fox, Yoshi's Island, Doom, Vortex, ...) look
	 * like a DSP-1 cart.</p>
	 *
	 * <p>References: <a href="https://snes.nesdev.org/wiki/ROM_header">
	 * SNESdev wiki -- ROM header</a>.</p>
	 */
	public Coprocessor getCoprocessor() {
		int hi = (cartridgeType >> 4) & 0x0F;
		int lo = cartridgeType & 0x0F;
		// lo 0..2 are plain ROM / ROM+RAM / ROM+RAM+battery -- no chip.
		// lo 3..6 indicate "ROM + chip"; the high nibble then names the chip.
		// Exception: some early DSP games (e.g. Super Bowling / DSP-2) set the
		// cartridge type byte to 0x00 even though a DSP chip is present. We use
		// the ROM title to override those known edge cases.
		if (lo < 3) {
			// Non-zero hi nibble unambiguously indicates a chip.
			if (hi != 0) return decodeCoprocessorFamily(hi);
			// hi == 0 is ambiguous (plain ROM or DSP-x). Check known overrides.
			return decodeDspOverrideByTitle();
		}
		return decodeCoprocessorFamily(hi);
	}

	private Coprocessor decodeCoprocessorFamily(int hi) {
		switch (hi) {
			case 0x0: return Coprocessor.DSP1;
			case 0x1: return Coprocessor.GSU;
			case 0x2: return Coprocessor.OBC1;
			case 0x3: return Coprocessor.SA1;
			case 0x4: return Coprocessor.SDD1;
			case 0x5: return Coprocessor.SRTC;
			case 0xE: return Coprocessor.OTHER;
			case 0xF: return decodeCustomCoprocessor();
			default:  return Coprocessor.CUSTOM_UNKNOWN;
		}
	}

	private Coprocessor decodeCustomCoprocessor() {
		switch (cartridgeType & 0xFF) {
			case 0xF3: return Coprocessor.CUSTOM_CX4;
			case 0xF5: return Coprocessor.CUSTOM_SPC7110;
			case 0xF9: return Coprocessor.CUSTOM_SPC7110;
			case 0xF6: return Coprocessor.CUSTOM_ST010_011;
			case 0xF8: return Coprocessor.CUSTOM_ST018;
			default:   return Coprocessor.CUSTOM_UNKNOWN;
		}
	}

	/**
	 * Some early DSP games (DSP-1/2/3/4) have a coprocessor but set the
	 * cartridge type byte to 0x00, which the standard decode rules treat
	 * as "plain ROM / no chip". Override by ROM title for known titles.
	 */
	private Coprocessor decodeDspOverrideByTitle() {
		// The ROM title is the first 21 bytes of the header at $00:FFC0.
		String t = getTitle();
		if (t == null || t.isEmpty()) return Coprocessor.NONE;
		// Known DSP games that don't set the cartridge type byte.
		if (t.startsWith("SUPER BOWLING")) return Coprocessor.DSP1;
		// Add more title overrides here as discovered.
		return Coprocessor.NONE;
	}

	public boolean isSa1() { return getCoprocessor() == Coprocessor.SA1; }
	public boolean isSuperFx() { return getCoprocessor() == Coprocessor.GSU; }
	public boolean isSdd1() { return getCoprocessor() == Coprocessor.SDD1; }
	public boolean isCx4() { return getCoprocessor() == Coprocessor.CUSTOM_CX4; }
	public boolean isSpc7110() { return getCoprocessor() == Coprocessor.CUSTOM_SPC7110; }

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
		if (isExLoRomMode()) sb.append("ExLoROM/ExHiROM");
		else if (isSpc7110Mode()) sb.append("HiROM/SPC7110");
		else if (isSa1Mode()) sb.append("LoROM/SA-1");
		else if (isLoRomMode()) sb.append("LoROM");
		else if (isHiRomMode()) sb.append("HiROM");
		else sb.append("Unknown");
		if (isFastRom()) sb.append(", FastROM");
		sb.append(String.format(" (mapMode=$%02X)", mapMode));
		return sb.toString();
	}

	public String describeCartridgeType() {
		Coprocessor cp = getCoprocessor();
		int lo = cartridgeType & 0x0F;
		String comp;
		switch (lo) {
			case 0x0: comp = "ROM"; break;
			case 0x1: comp = "ROM+RAM"; break;
			case 0x2: comp = "ROM+RAM+battery"; break;
			case 0x3: comp = "ROM+chip"; break;
			case 0x4: comp = "ROM+chip+RAM"; break;
			case 0x5: comp = "ROM+chip+RAM+battery"; break;
			case 0x6: comp = "ROM+chip+battery"; break;
			default:  comp = String.format("type=$%X", lo); break;
		}
		if (cp.isPresent()) {
			return comp + " + " + cp.describe();
		}
		return comp;
	}

	public String describe() {
		return String.format(
			"title='%s' mapMode=%s cart=%s romSizeCode=$%02X (%dKB) sramCode=$%02X (%dKB) " +
			"region=%s version=$%02X resetVec=$%04X checksum=$%04X complement=$%04X",
			title, describeMapMode(), describeCartridgeType(),
			romSize, getRomBytes() / 1024,
			ramSize, getSramBytes() / 1024,
			describeRegion(), version, getResetVector(), checksum, complement);
	}
}

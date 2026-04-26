// SPDX-License-Identifier: MIT
package snesloader;

import java.io.IOException;

import ghidra.app.util.bin.ByteProvider;

/**
 * Parameters for one specific way of interpreting the ROM bytes:
 * a {@link RomKind} (LoROM/HiROM mapping) plus the presence/absence of an
 * optional 512-byte SMC copier header. Once {@link #bytesLookValid(ByteProvider)}
 * has run successfully the parsed {@link SnesHeader} is cached on the instance.
 */
public class RomInfo {

	public static final int SMC_HEADER_LEN = 512;

	public enum RomKind {
		/** Mode 20/22/30/32. ROM seen at $00:8000, banks of 32 KiB. */
		LO_ROM(0x7FC0, 0x40_0000, 0x8000, LoRomLoader::load),
		/** Mode 21/25/31/35. ROM seen at $C0:0000, banks of 64 KiB. */
		HI_ROM(0xFFC0, 0x40_0000, 0x10000, HiRomLoader::load);

		private final long snesHeaderOffset;
		private final long maxRomSize;
		private final long chunkSize;
		private final RomLoader loader;

		RomKind(long snesHeaderOffset, long maxRomSize, long chunkSize, RomLoader loader) {
			this.snesHeaderOffset = snesHeaderOffset;
			this.maxRomSize = maxRomSize;
			this.chunkSize = chunkSize;
			this.loader = loader;
		}

		public long getSnesHeaderOffset() { return snesHeaderOffset; }
		public long getMaxRomSize() { return maxRomSize; }
		public long getChunkSize() { return chunkSize; }
		public RomLoader getLoader() { return loader; }
	}

	private final RomKind kind;
	private final boolean hasSmcHeader;
	private SnesHeader header;

	public RomInfo(RomKind kind, boolean hasSmcHeader) {
		this.kind = kind;
		this.hasSmcHeader = hasSmcHeader;
	}

	public boolean bytesLookValid(ByteProvider provider) {
		try {
			long romLen = provider.length() - getStartOffset();
			if (romLen < kind.getChunkSize()) {
				return false;
			}
			if (romLen > kind.getMaxRomSize() * 2) {
				return false;
			}
			// Try the standard header offset first.
			SnesHeader h = tryHeaderAt(provider, getSnesHeaderOffset());
			// For HiROM, also try the ExHiROM upper-ROM header location
			// ($40:FFC0, ROM offset 0x40FFC0) when the standard offset fails.
			// Some ExHiROM cartridges (>4 MiB) place their header in the upper
			// ROM banks rather than at the standard $C0:FFC0.
			if (h == null && kind == RomKind.HI_ROM && romLen > kind.getMaxRomSize()) {
				long exHiromOffset = kind.getMaxRomSize() + 0xFFC0L;
				if (exHiromOffset + 48 <= provider.length()) {
					h = tryHeaderAt(provider, exHiromOffset);
				}
			}
			if (h == null) return false;
			if (kind == RomKind.LO_ROM && !h.isLoRomMode()) {
				return false;
			}
			if (kind == RomKind.HI_ROM && !h.isHiRomMode()) {
				return false;
			}
			this.header = h;
			return true;
		}
		catch (IOException e) {
			return false;
		}
	}

	private SnesHeader tryHeaderAt(ByteProvider provider, long offset) {
		try {
			SnesHeader h = SnesHeader.fromProviderAtOffset(provider, offset);
			if (h.looksValid()) return h;
			return null;
		}
		catch (IOException e) {
			return null;
		}
	}

	public long getStartOffset() {
		return hasSmcHeader ? SMC_HEADER_LEN : 0L;
	}

	public long getSnesHeaderOffset() {
		return getStartOffset() + kind.getSnesHeaderOffset();
	}

	public long getRomChunkSize() {
		return kind.getChunkSize();
	}

	public RomKind getKind() {
		return kind;
	}

	public boolean hasSmcHeader() {
		return hasSmcHeader;
	}

	public SnesHeader getHeader() {
		return header;
	}

	public RomLoader getLoader() {
		return kind.getLoader();
	}

	public String getDescription() {
		return kind.toString() + (hasSmcHeader ? " (SMC)" : "");
	}

	@Override
	public int hashCode() {
		return (kind.ordinal() << 1) | (hasSmcHeader ? 1 : 0);
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) return true;
		if (!(obj instanceof RomInfo)) return false;
		RomInfo other = (RomInfo) obj;
		return kind == other.kind && hasSmcHeader == other.hasSmcHeader;
	}
}
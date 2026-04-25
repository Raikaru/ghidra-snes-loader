// SPDX-License-Identifier: MIT
package snesloader;

import java.io.IOException;
import java.util.List;

import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.LoadSpec;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOverflowException;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

import snesloader.RomReader.RomChunk;

/**
 * Memory mapping for HiROM (mode 21 / 31) and ExHiROM (mode 25 / 35):
 * <pre>
 * HiROM:
 *   Banks $C0-$FF : ROM at $0000-$FFFF (full 64 KiB banks) — lower 4 MiB.
 *   Banks $40-$7D : ROM mirror of $C0-x.
 *   Banks $80-$BF : upper-half mirrors of $C0-x at $8000-$FFFF (FastROM).
 *   Banks $00-$3F : upper-half mirrors of $C0-x at $8000-$FFFF (slow).
 *   Banks $7E-$7F : WRAM (handled by SnesPostLoader, not here).
 *
 * ExHiROM (mode 25/35):
 *   Banks $C0-$FF : ROM at $0000-$FFFF — lower 4 MiB (same as HiROM).
 *   Banks $40-$7F : ROM at $0000-$FFFF — upper 4 MiB (NOT mirrors).
 *   Banks $80-$BF : upper-half mirrors of lower ROM at $8000-$FFFF (FastROM).
 *   Banks $00-$3F : upper-half mirrors of lower ROM at $8000-$FFFF (slow).
 * </pre>
 *
 * For each 64 KiB chunk we lay down one initialised primary block and
 * two byte-mapped mirrors (upper-half views, lower chunks only).
 * The $40-x full-bank mirrors are only created for HiROM (not ExHiROM,
 * where $40-x is the upper ROM). ExHiROM upper chunks have no upper-half
 * mirrors — they're accessed full-bank at $40-$7F.
 */
public class HiRomLoader {

	public static final long SNES_HEADER_OFFSET = 0xFFC0;
	public static final long MAX_ROM_SIZE = 0x40_0000;
	public static final int ROM_CHUNK_SIZE = 0x10000;

	public static boolean load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			MessageLog log, Program prog, TaskMonitor monitor, RomInfo romInfo) throws IOException {
		AddressSpace bus = prog.getAddressFactory().getDefaultAddressSpace();
		boolean isExHiRom = romInfo != null && romInfo.getHeader() != null
			&& romInfo.getHeader().isExHiRomMode();

		int idx = 0;
		boolean truncationWarned = false;
		RomReader reader = new RomReader(romInfo, provider);
		for (RomChunk chunk : reader) {
			boolean isUpperChunk = isExHiRom && idx >= 64;
			long bankOffset = isUpperChunk ? idx - 64 : idx;

			if (isUpperChunk) {
				if (bankOffset >= 64) {
					if (!truncationWarned) {
						log.appendMsg(SnesLoader.LOADER_NAME, String.format(
							"ROM is %d KiB, larger than the ExHiROM 8 MiB ceiling. " +
							"Mapping the first 8 MiB only.", provider.length() / 1024));
						truncationWarned = true;
					}
					idx++;
					continue;
				}
			} else if (idx >= 64) {
				if (!truncationWarned) {
					log.appendMsg(SnesLoader.LOADER_NAME, String.format(
						"ROM is %d KiB, larger than the HiROM 4 MiB ceiling. " +
						"Mapping the first 4 MiB only; the remaining bytes " +
						"are reachable via the file's flat byte view but not the " +
						"24-bit bus.", provider.length() / 1024));
					truncationWarned = true;
				}
				idx++;
				continue;
			}

			// Primary block
			long baseBank = isUpperChunk ? 0x40L : 0xC0L;
			Address primary = bus.getAddress((baseBank + bankOffset) << 16);
			String primaryName = String.format("rom_%02X_0000-%02X_FFFF (%s bank %02X)",
					(int) (baseBank + bankOffset), (int) (baseBank + bankOffset),
					isUpperChunk ? "ExHiROM upper" : "HiROM", (int) (baseBank + bankOffset));
			try {
				MemoryBlockUtils.createInitializedBlock(prog, false, primaryName, primary,
						chunk.getInputStream(), chunk.getLength(), "ROM (HiROM)",
						provider.getAbsolutePath(), true, false, true, log, monitor);
			}
			catch (AddressOverflowException e) {
				throw new IOException("Failed to map HiROM chunk at " + primary, e);
			}

			// Upper-half mirrors ($80+i:8000 and $00+i:8000).
			// ExHiROM upper chunks are at $40-$7F:0000-$FFFF (full bank);
			// they have no upper-half mirrors in $80-x/$00-x.
			if (!isUpperChunk) {
				Address fastUpper = bus.getAddress((0x80L + bankOffset) << 16 | 0x8000L);
				MemoryBlockUtils.createByteMappedBlock(prog,
					String.format("rom_%02X_8000_mirror1", (int) (0x80 + bankOffset)),
					fastUpper, primary.add(0x8000),
					0x8000, "FastROM upper-half mirror of " + primaryName, "", true, false, true,
					false, log);

				Address slowUpper = bus.getAddress((0x00L + bankOffset) << 16 | 0x8000L);
				MemoryBlockUtils.createByteMappedBlock(prog,
					String.format("rom_%02X_8000_mirror2", (int) bankOffset),
					slowUpper, primary.add(0x8000),
					0x8000, "Slow upper-half mirror of " + primaryName, "", true, false, true,
					false, log);
			}

			// Full-bank mirror at $40+i:0000 (slow), banks 0x40-0x7D only.
			// Skipped for ExHiROM (those banks are the upper ROM).
			if (!isExHiRom && idx < 0x3D) {
				Address slowFull = bus.getAddress(((0x40L + idx) & 0xFF) << 16);
				MemoryBlockUtils.createByteMappedBlock(prog,
					String.format("rom_%02X_0000_mirror", 0x40 + idx),
					slowFull, primary,
					0x10000, "Slow full-bank mirror of " + primaryName, "", true, false, true,
					false, log);
			}

			idx++;
		}
		return true;
	}
}

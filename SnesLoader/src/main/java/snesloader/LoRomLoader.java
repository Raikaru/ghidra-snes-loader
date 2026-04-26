// SPDX-License-Identifier: MIT
package snesloader;

import java.io.IOException;
import java.util.ArrayList;
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
 * Memory mapping for LoROM (mode 20 / 30 — also 22 / 32 for SA-1/SDD-1 variants)
 * and ExLoROM (mode 25 / 35):
 * <pre>
 * Standard LoROM:
 *   Banks $00-$3F : ROM at $8000-$FFFF (32 KiB chunk per bank) — lower 2 MiB
 *   Banks $80-$BF : FastROM mirror of $00-$3F
 *   Banks $40-$7D : ROM at $8000-$FFFF — upper 2 MiB of the basic 4 MiB
 *   Banks $C0-$FF : FastROM mirror of $40-$7D
 *   Banks $40-$5F : ROM extension at $0000-$7FFF — data ROM past 4 MiB (SDD-1 etc.)
 *   Banks $7E-$7F : WRAM (created later by SnesPostLoader, not here)
 *
 * ExLoROM (mode 25/35):
 *   Banks $80-$FF : ROM at $8000-$FFFF (32 KiB chunk per bank) — lower 4 MiB
 *   Banks $00-$7D : ROM at $8000-$FFFF — upper 4 MiB
 *   Banks $7E-$7F : WRAM (created later by SnesPostLoader, not here)
 * </pre>
 *
 * For each 32 KiB ROM chunk we lay down one initialised primary block and
 * one byte-mapped mirror so FastROM-region accesses resolve. Chunks past
 * 4 MiB are mapped into the lower half of banks $40-$5F (unused in standard
 * LoROM) so the physical SDD-1 / data ROM bytes are available to the analyst.
 * ExLoROM chunks past 4 MiB are mapped into banks $00-$7D.
 */
public class LoRomLoader {

	public static final long SNES_HEADER_OFFSET = 0x7FC0;
	public static final long MAX_ROM_SIZE = 0x40_0000;
	public static final int ROM_CHUNK_SIZE = 0x8000;

	public static boolean load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			MessageLog log, Program prog, TaskMonitor monitor, RomInfo romInfo) throws IOException {
		AddressSpace bus = prog.getAddressFactory().getDefaultAddressSpace();
		boolean isExLoRom = romInfo != null && romInfo.getHeader() != null
			&& romInfo.getHeader().isExLoRomMode();

		RomReader reader = new RomReader(romInfo, provider);
		boolean truncationWarned = false;
		for (RomChunk chunk : reader) {
			long romStart = chunk.getRomStart();

			if (romStart >= MAX_ROM_SIZE) {
				if (isExLoRom) {
					// ExLoROM: map past 4 MiB into banks $00-$7D at $8000-$FFFF.
					long extChunkIdx = (romStart - MAX_ROM_SIZE) / 0x8000L;
					long bank = extChunkIdx;
					if (bank >= 0x7E) {
						if (!truncationWarned) {
							log.appendMsg(SnesLoader.LOADER_NAME, String.format(
								"ROM is %d KiB, mapping the first 8 MiB only; the remaining " +
								"bytes are reachable via the file's flat byte view.",
								provider.length() / 1024));
							truncationWarned = true;
						}
						continue;
					}
					Address primary = bus.getAddress((bank << 16) | 0x8000L);
					String primaryName = String.format(
						"rom_exlo_%02X_8000-%02X_FFFF (ExLoROM upper / file %06X-%06X)",
						(int) bank, (int) bank, romStart, chunk.getRomEnd());
					try {
						MemoryBlockUtils.createInitializedBlock(prog, false, primaryName, primary,
								chunk.getInputStream(), chunk.getLength(),
								"ROM (ExLoROM upper)",
								provider.getAbsolutePath(), true, false, true, log, monitor);
					}
					catch (AddressOverflowException e) {
						throw new IOException(
							"Failed to map ExLoROM upper chunk at " + primary, e);
					}
					continue;
				}

				// Standard LoROM: past 4 MiB. Map into lower halves of banks $40-$5F.
				long extChunkIdx = (romStart - MAX_ROM_SIZE) / 0x8000L;
				long bank = 0x40L + extChunkIdx;
				if (bank >= 0x60) {
					if (!truncationWarned) {
						log.appendMsg(SnesLoader.LOADER_NAME, String.format(
							"ROM is %d KiB, mapping the first 5 MiB only; the remaining " +
							"bytes are reachable via the file's flat byte view.",
							provider.length() / 1024));
						truncationWarned = true;
					}
					continue;
				}
				Address primary = bus.getAddress((bank << 16) | 0x0000L);
				String primaryName = String.format(
					"rom_ext_%02X_0000-%02X_7FFF (SDD-1 data / file %06X-%06X)",
					(int) bank, (int) bank, romStart, chunk.getRomEnd());
				try {
					MemoryBlockUtils.createInitializedBlock(prog, false, primaryName, primary,
							chunk.getInputStream(), chunk.getLength(),
							"ROM extension (SDD-1 / data ROM beyond 4 MiB)",
							provider.getAbsolutePath(), true, false, true, log, monitor);
				}
				catch (AddressOverflowException e) {
					throw new IOException(
						"Failed to map extended LoROM chunk at " + primary, e);
				}
				continue;
			}

			List<Address> addresses = busAddressesFor(chunk, bus, isExLoRom);
			Address primary = addresses.remove(0);
			String primaryName = chunkPrimaryName(chunk, isExLoRom);
			try {
				MemoryBlockUtils.createInitializedBlock(prog, false, primaryName, primary,
						chunk.getInputStream(), chunk.getLength(), "ROM (LoROM)",
						provider.getAbsolutePath(), true, false, true, log, monitor);
			}
			catch (AddressOverflowException e) {
				throw new IOException("Failed to map LoROM chunk at " + primary, e);
			}

			int idx = 1;
			for (Address mirror : addresses) {
				String mirrorName = String.format("%s_mirror%d", primaryName, idx++);
				MemoryBlockUtils.createByteMappedBlock(prog, mirrorName, mirror, primary,
						(int) chunk.getLength(), "mirror of " + primaryName, "", true, false, true,
						false, log);
			}
		}
		return true;
	}

	private static List<Address> busAddressesFor(RomChunk chunk, AddressSpace bus, boolean isExLoRom) {
		List<Address> out = new ArrayList<>();
		long romStart = chunk.getRomStart();

		if (isExLoRom) {
			// ExLoROM: primary at banks $80-$FF:8000-$FFFF.
			long bank = 0x80L + (romStart / 0x8000L);
			if (bank <= 0xFF) {
				long primary = (bank << 16) | 0x8000L;
				out.add(bus.getAddress(primary));
			}
			// FastROM mirror at the same bank + 0x00 offset? No mirror needed for ExLoROM.
			// The FastROM region is the same bank range accessed with different timing.
			return out;
		}

		// Standard LoROM: primary $00-$3F (skipping $3F:8000 overflow into WRAM).
		if (romStart <= 0x3E_8000L) {
			long primary = ((romStart / 0x8000L) * 0x1_0000L) + 0x8000L;
			out.add(bus.getAddress(primary));
		}
		// FastROM mirror $80-$BF (and $40-$6F for the rest of a 4 MB image).
		long mirror = ((romStart / 0x8000L) * 0x1_0000L) + 0x80_8000L;
		out.add(bus.getAddress(mirror));
		return out;
	}

	private static String chunkPrimaryName(RomChunk chunk, boolean isExLoRom) {
		long s = chunk.getRomStart();
		long e = chunk.getRomEnd();

		if (isExLoRom) {
			long bank = 0x80L + (s / 0x8000L);
			return String.format("rom_%02X_8000-%02X_FFFF (ExLoROM / file %06X-%06X)",
					(int) bank, (int) bank, s, e);
		}

		long primary = ((s / 0x8000L) * 0x1_0000L) + 0x8000L;
		long primaryEnd = primary | 0xFFFFL;
		int sb = (int) ((primary >> 16) & 0xFF);
		int eb = (int) ((primaryEnd >> 16) & 0xFF);
		return String.format("rom_%02X_%04X-%02X_%04X (file %06X-%06X)",
				sb, (int) (primary & 0xFFFF), eb, (int) (primaryEnd & 0xFFFF), s, e);
	}
}
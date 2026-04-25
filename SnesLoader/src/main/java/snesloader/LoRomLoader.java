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
 * Memory mapping for LoROM (mode 20 / 30 — also 22 / 32 for SA-1/SDD-1 variants):
 * <pre>
 *   Banks $00-$3F : ROM at $8000-$FFFF (32 KiB chunk per bank)
 *   Banks $80-$BF : same primary mirror as $00-$3F (FastROM access)
 *   Banks $40-$6F : ROM extension for >4 MiB LoROM (SDD-1 data ROM, etc.)
 *   Banks $7E-$7F : WRAM (created later by SnesPostLoader, not here)
 * </pre>
 * For each 32 KiB ROM chunk we lay down one initialised primary block at
 * $bb:8000 and one byte-mapped mirror at $(bb+0x80):8000 so that FastROM-
 * region accesses resolve. Chunks past 4 MiB are mapped into banks $40-$6F
 * (typically unused in standard LoROM) so the physical ROM data is available.
 */
public class LoRomLoader {

	public static final long SNES_HEADER_OFFSET = 0x7FC0;
	public static final long MAX_ROM_SIZE = 0x40_0000;
	public static final int ROM_CHUNK_SIZE = 0x8000;

	public static boolean load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			MessageLog log, Program prog, TaskMonitor monitor, RomInfo romInfo) throws IOException {
		AddressSpace bus = prog.getAddressFactory().getDefaultAddressSpace();

		RomReader reader = new RomReader(romInfo, provider);
		boolean truncationWarned = false;
		for (RomChunk chunk : reader) {
			long romStart = chunk.getRomStart();

			// Standard LoROM: 0 to 4 MiB → banks $00-$3F/$80-$BF at $8000.
			// Extended LoROM: 4 to 8 MiB → banks $40-$6F at $8000 (for SDD-1 data ROM, etc.).
			if (romStart >= MAX_ROM_SIZE) {
				if (romStart >= 0x80_0000L) {
					// Beyond 8 MiB ceiling — truncate.
					if (!truncationWarned) {
						log.appendMsg(SnesLoader.LOADER_NAME, String.format(
							"ROM is %d KiB, larger than the LoROM extended 8 MiB ceiling. " +
							"Mapping the first 8 MiB only.", provider.length() / 1024));
						truncationWarned = true;
					}
					continue;
				}
				// The $40-$6F range (3 MiB at $8000) gives room for an additional
				// 6 MiB of extension, but the address calculation for mirrors in
				// $80-x would overflow. Create only the primary block.
				long extOffset = romStart - MAX_ROM_SIZE; // 0..4 MiB into extension region
				long bank = 0x40L + (extOffset / 0x8000L);
				Address primary = bus.getAddress((bank << 16) | 0x8000L);
				String primaryName = String.format("rom_ext_%02X_8000-%02X_FFFF (file %06X-%06X)",
						(int) bank, (int) bank, romStart, chunk.getRomEnd());
				try {
					MemoryBlockUtils.createInitializedBlock(prog, false, primaryName, primary,
							chunk.getInputStream(), chunk.getLength(),
							"ROM extension (SDD-1 / data ROM beyond 4 MiB)",
							provider.getAbsolutePath(), true, false, true, log, monitor);
				}
				catch (AddressOverflowException e) {
					throw new IOException("Failed to map extended LoROM chunk at " + primary, e);
				}
				continue;
			}

			List<Address> addresses = busAddressesFor(chunk, bus);
			Address primary = addresses.remove(0);
			String primaryName = chunkPrimaryName(chunk);
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

	private static List<Address> busAddressesFor(RomChunk chunk, AddressSpace bus) {
		List<Address> out = new ArrayList<>();
		long romStart = chunk.getRomStart();

		// Primary $00-$3F (skipping the 0x3F:8000 overflow into 7E/7F WRAM region).
		if (romStart <= 0x3E_8000L) {
			long primary = ((romStart / 0x8000L) * 0x1_0000L) + 0x8000L;
			out.add(bus.getAddress(primary));
		}
		// FastROM mirror $80-$BF (and $40-$6F for the rest of a 4 MB image).
		long mirror = ((romStart / 0x8000L) * 0x1_0000L) + 0x80_8000L;
		out.add(bus.getAddress(mirror));
		return out;
	}

	private static String chunkPrimaryName(RomChunk chunk) {
		long s = chunk.getRomStart();
		long e = chunk.getRomEnd();
		long primary = ((s / 0x8000L) * 0x1_0000L) + 0x8000L;
		long primaryEnd = primary | 0xFFFFL;
		int sb = (int) ((primary >> 16) & 0xFF);
		int eb = (int) ((primaryEnd >> 16) & 0xFF);
		return String.format("rom_%02X_%04X-%02X_%04X (file %06X-%06X)",
				sb, (int) (primary & 0xFFFF), eb, (int) (primaryEnd & 0xFFFF), s, e);
	}
}

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
 * Memory mapping for LoROM (mode 20 / 30 — also 22 / 32 for SA-1 variants):
 * <pre>
 *   Banks $00-$3F : ROM at $8000-$FFFF (32 KiB chunk per bank)
 *   Banks $80-$BF : same primary mirror as $00-$3F (FastROM access)
 *   Banks $40-$6F : usually unused or further ROM mirror; we mirror $80-$AF only.
 *   Banks $7E-$7F : WRAM (created later by SnesPostLoader, not here)
 * </pre>
 * For each 32 KiB ROM chunk we lay down one initialised primary block at
 * $bb:8000 and one byte-mapped mirror at $(bb+0x80):8000 so that FastROM-
 * region accesses resolve.
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
			// LoROM chunk indices past the 4 MiB ceiling cannot be expressed
			// in the 24-bit SNES bus and must be skipped. This shows up on
			// SPC7110 cartridges (Star Ocean, Far East of Eden Zero) when
			// the auto-detection coincidentally picks LoROM over the real
			// HiROM/SPC7110 mapping. Without this guard busAddressesFor
			// throws AddressOutOfBoundsException with offset 0x1008000.
			if (chunk.getRomStart() >= MAX_ROM_SIZE) {
				if (!truncationWarned) {
					log.appendMsg(SnesLoader.LOADER_NAME, String.format(
						"ROM is %d KiB, larger than the LoROM 4 MiB ceiling. " +
						"Mapping the first 4 MiB only; the remaining bytes are " +
						"reachable via the file's flat byte view but not the " +
						"24-bit bus.", provider.length() / 1024));
					truncationWarned = true;
				}
				continue;
			}
			List<Address> mirrors = busAddressesFor(chunk, bus);
			Address primary = mirrors.remove(0);
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
			for (Address mirror : mirrors) {
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

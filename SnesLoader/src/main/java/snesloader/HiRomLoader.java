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
 * Memory mapping for HiROM (mode 21 / 31 — also 25 / 35 ExHiROM):
 * <pre>
 *   Banks $C0-$FF : ROM at $0000-$FFFF (full 64 KiB banks).
 *   Banks $40-$7D : ROM mirror with the same offset as $C0+x.
 *   Banks $00-$3F : ROM upper-half mirror at $8000-$FFFF (LowRAM lives at
 *                   $0000-$1FFF, hardware regs at $2000-$5FFF).
 *   Banks $80-$BF : same upper-half mirror as $00-$3F (FastROM region).
 *   Banks $7E-$7F : WRAM (handled by SnesPostLoader, not here).
 * </pre>
 *
 * For each 64 KiB chunk we lay down one initialised primary block at
 * $C0+i:0000 and three byte-mapped mirrors:
 * <ul>
 *   <li>$80+i:8000 (FastROM upper-half view, banks 0x80..0xBF)</li>
 *   <li>$00+i:8000 (slow upper-half view, banks 0x00..0x3F)</li>
 *   <li>$40+i:0000 (slow full-bank mirror, banks 0x40..0x7D)</li>
 * </ul>
 * The slow full-bank mirror at $40+i is only created for i &lt; 0x3D (we have to
 * skip $7E/$7F because that's WRAM).
 */
public class HiRomLoader {

	public static final long SNES_HEADER_OFFSET = 0xFFC0;
	public static final long MAX_ROM_SIZE = 0x40_0000;
	public static final int ROM_CHUNK_SIZE = 0x10000;

	public static boolean load(ByteProvider provider, LoadSpec loadSpec, List<Option> options,
			MessageLog log, Program prog, TaskMonitor monitor, RomInfo romInfo) throws IOException {
		AddressSpace bus = prog.getAddressFactory().getDefaultAddressSpace();

		int idx = 0;
		RomReader reader = new RomReader(romInfo, provider);
		for (RomChunk chunk : reader) {
			Address primary = bus.getAddress(((0xC0L + idx) & 0xFF) << 16);
			String primaryName = String.format("rom_%02X_0000-%02X_FFFF (HiROM bank %02X)",
					(int) ((primary.getOffset() >> 16) & 0xFF),
					(int) ((primary.getOffset() >> 16) & 0xFF), 0xC0 + idx);
			try {
				MemoryBlockUtils.createInitializedBlock(prog, false, primaryName, primary,
						chunk.getInputStream(), chunk.getLength(), "ROM (HiROM)",
						provider.getAbsolutePath(), true, false, true, log, monitor);
			}
			catch (AddressOverflowException e) {
				throw new IOException("Failed to map HiROM chunk at " + primary, e);
			}

			// Upper-half mirror at $80+i:8000 (FastROM view).
			Address fastUpper = bus.getAddress(((0x80L + idx) & 0xFF) << 16 | 0x8000L);
			MemoryBlockUtils.createByteMappedBlock(prog,
					String.format("rom_%02X_8000_mirror1", 0x80 + idx),
					fastUpper, primary.add(0x8000),
					0x8000, "FastROM upper-half mirror of " + primaryName, "", true, false, true,
					false, log);

			// Upper-half mirror at $00+i:8000 (slow CPU bus).
			Address slowUpper = bus.getAddress(((0x00L + idx) & 0xFF) << 16 | 0x8000L);
			MemoryBlockUtils.createByteMappedBlock(prog,
					String.format("rom_%02X_8000_mirror2", idx),
					slowUpper, primary.add(0x8000),
					0x8000, "Slow upper-half mirror of " + primaryName, "", true, false, true,
					false, log);

			// Full-bank mirror at $40+i:0000 (slow), banks 0x40-0x7D only.
			if (idx < 0x3D) {
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

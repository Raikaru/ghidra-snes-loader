// SPDX-License-Identifier: MIT
package snesloader;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.MemoryBlockUtils;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataUtilities;
import ghidra.program.model.data.DataUtilities.ClearDataMode;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Layers Ghidra-friendly metadata over the raw ROM mapping produced by
 * {@link LoRomLoader}/{@link HiRomLoader}: WRAM, hardware register block,
 * SRAM, the cartridge header structure and the native + emulation vector
 * tables.
 */
public final class SnesPostLoader {

	public static final long WRAM_START = 0x7E_0000L;
	public static final long WRAM_LEN = 0x2_0000L;       // 128 KiB ($7E:0000-$7F:FFFF)
	public static final long LOWRAM_BUS_START = 0x00_0000L;
	public static final long LOWRAM_LEN = 0x2000L;        // $00:0000-$00:1FFF
	public static final long HW_REGS_BUS_START = 0x00_2000L;
	public static final long HW_REGS_LEN = 0x2400L;       // $00:2000-$00:43FF (covers MSU-1 + expansion)
	/**
	 * Banks where the LowRAM mirror and the hardware-register window are
	 * visible to the 65816. The SNES bus mirrors WRAM low-bank ($7E:0000-$1FFF)
	 * and the I/O window ($2000-$5FFF) into both the slow ($00-$3F) and fast
	 * ($80-$BF) bank ranges. Without these mirrors, code that runs in (say)
	 * bank $32 with DBR=$32 cannot resolve a {@code LDA $0080} or
	 * {@code STA $2100} to the canonical backing store, and the decompiler
	 * shows a bare 24-bit address.
	 */
	private static final int[] MIRROR_BANK_RANGES = {
		0x00, 0x3F,   // slow CPU bus
		0x80, 0xBF    // FastROM CPU bus
	};
	public static final long SRAM_LO_START = 0x70_0000L;  // LoROM SRAM appears in $70-$7D:0000-$7FFF
	public static final long SRAM_HI_START = 0x30_6000L;  // HiROM SRAM appears in $30-$3F:6000-$7FFF (fastrom mirror)

	public static final long NATIVE_VECTORS_ADDR = 0x00_FFE4L;
	public static final long EMU_VECTORS_ADDR = 0x00_FFF4L;
	public static final long CART_HEADER_ADDR_LOROM = 0x00_FFC0L;
	public static final long CART_HEADER_ADDR_HIROM = 0x00_FFC0L;

	public static final class Options {
		public boolean mapHwRegs = true;
		public boolean markVectors = true;
		public boolean applyHeaderDataType = true;
		public boolean mapLowRamMirror = true;
		public boolean mapSram = true;
		public boolean mapMsu1 = true;
		public boolean labelCoprocessor = true;
		public boolean mirrorHwRegLabels = true;
	}

	private SnesPostLoader() {}

	public static void apply(FlatProgramAPI fpa, RomInfo romInfo, Options opts, MessageLog log) {
		Program program = fpa.getCurrentProgram();
		AddressSpace bus = program.getAddressFactory().getDefaultAddressSpace();

		// 1) WRAM (always; it's required to make the program runnable).
		mapWramBlocks(program, bus, log);
		if (opts.mapLowRamMirror) {
			mapLowRamMirror(program, bus, log);
		}

		// 2) Hardware-register region.
		if (opts.mapHwRegs) {
			mapHwRegs(program, bus, log);
			SnesHardware.applyLabels(fpa, log, opts.mirrorHwRegLabels);
			if (opts.mapMsu1) {
				SnesHardware.applyMsu1Labels(fpa, log);
			}
			if (opts.labelCoprocessor && romInfo.getHeader() != null) {
				SnesHardware.applyCoprocessorLabels(fpa,
					romInfo.getHeader().getCoprocessor(), log);
			}
		}

		// 3) Cartridge SRAM (when the header indicates one is present).
		if (opts.mapSram && romInfo.getHeader() != null && romInfo.getHeader().getSramBytes() > 0) {
			mapSram(program, bus, romInfo, log);
		}

		// 4) Cartridge header struct.
		if (opts.applyHeaderDataType && romInfo.getHeader() != null) {
			applyCartridgeHeaderType(program, bus, log);
		}

		// 5) Native + emulation vector tables, plus entry point.
		if (opts.markVectors && romInfo.getHeader() != null) {
			SnesVectors.apply(fpa, bus, romInfo, log);
		}

		// 6) Surface a high-level program comment with the decoded header info
		// so a glance at the disassembly tells the analyst what cart this is.
		if (romInfo.getHeader() != null) {
			try {
				program.setExecutableFormat(SnesLoader.LOADER_NAME);
			}
			catch (Exception ignored) {}
			Address resetEntry = bus.getAddress(romInfo.getHeader().getResetVector() & 0xFFFFL);
			try {
				fpa.setPlateComment(resetEntry,
					"SNES " + romInfo.getKind()
						+ (romInfo.hasSmcHeader() ? " (SMC)" : "")
						+ "\n" + romInfo.getHeader().describe());
			}
			catch (Exception ignored) {}
		}
	}

	private static void mapWramBlocks(Program program, AddressSpace bus, MessageLog log) {
		Address start = bus.getAddress(WRAM_START);
		MemoryBlockUtils.createUninitializedBlock(program, false, "wram", start, WRAM_LEN,
				"Work RAM ($7E:0000-$7F:FFFF, 128 KiB)", "", true, true, false, log);
	}

	private static void mapLowRamMirror(Program program, AddressSpace bus, MessageLog log) {
		// Primary mirror at $00:0000 (the canonical name retained for
		// backward-compatible scripts).
		Address start = bus.getAddress(LOWRAM_BUS_START);
		Address wramBase = bus.getAddress(WRAM_START);
		MemoryBlockUtils.createByteMappedBlock(program, "lowram_mirror", start, wramBase,
				(int) LOWRAM_LEN, "LowRAM mirror of $7E:0000-$1FFF visible in banks $00-$3F",
				"", true, true, false, false, log);
		// Plus one byte-mapped mirror per bank in $01-$3F and $80-$BF so the
		// decompiler resolves direct/absolute reads from any DBR-tracked bank.
		for (int range = 0; range < MIRROR_BANK_RANGES.length; range += 2) {
			int lo = MIRROR_BANK_RANGES[range];
			int hi = MIRROR_BANK_RANGES[range + 1];
			for (int bank = lo; bank <= hi; bank++) {
				if (bank == 0x00) continue; // already created above
				Address mirror = bus.getAddress(((long) bank) << 16 | LOWRAM_BUS_START);
				MemoryBlockUtils.createByteMappedBlock(program,
					String.format("lowram_mirror_%02X", bank),
					mirror, wramBase, (int) LOWRAM_LEN,
					String.format("LowRAM mirror of $7E:0000-$1FFF visible at $%02X:0000-$%02X:1FFF",
						bank, bank),
					"", true, true, false, false, log);
			}
		}
	}

	private static void mapHwRegs(Program program, AddressSpace bus, MessageLog log) {
		// Primary uninitialised block at $00:2000-$00:43FF; the labels in
		// SnesHardware go on this block so they're surfaced everywhere a
		// mirror is visible.
		Address start = bus.getAddress(HW_REGS_BUS_START);
		MemoryBlockUtils.createUninitializedBlock(program, false, "hwregs", start, HW_REGS_LEN,
				"PPU/APU/CPU/DMA registers ($00:2000-$00:43FF)", "", true, true, false, log);
		// Mirror the hardware-register window into every bank where the SNES
		// bus exposes it. This stops {@code STA $2100} from a function whose
		// PHK/PLB pinned DBR to a non-zero bank from looking like an
		// unmapped stray write.
		for (int range = 0; range < MIRROR_BANK_RANGES.length; range += 2) {
			int lo = MIRROR_BANK_RANGES[range];
			int hi = MIRROR_BANK_RANGES[range + 1];
			for (int bank = lo; bank <= hi; bank++) {
				if (bank == 0x00) continue;
				Address mirror = bus.getAddress(((long) bank) << 16 | HW_REGS_BUS_START);
				MemoryBlockUtils.createByteMappedBlock(program,
					String.format("hwregs_mirror_%02X", bank),
					mirror, start, (int) HW_REGS_LEN,
					String.format("Hardware-register mirror at $%02X:2000-$%02X:43FF",
						bank, bank),
					"", true, true, false, false, log);
			}
		}
	}

	private static void mapSram(Program program, AddressSpace bus, RomInfo romInfo, MessageLog log) {
		int size = romInfo.getHeader().getSramBytes();
		Address start;
		String name;
		if (romInfo.getKind() == RomInfo.RomKind.HI_ROM) {
			start = bus.getAddress(SRAM_HI_START);
			name = "sram";
		}
		else {
			start = bus.getAddress(SRAM_LO_START);
			name = "sram";
		}
		MemoryBlockUtils.createUninitializedBlock(program, false, name, start, size,
				String.format("Battery-backed cartridge SRAM (%d KiB)", size / 1024),
				"", true, true, false, log);
	}

	private static void applyCartridgeHeaderType(Program program, AddressSpace bus, MessageLog log) {
		// Build a struct mirroring the in-ROM cartridge header at $00:FFC0..$00:FFFF.
		StructureDataType s = new StructureDataType("SnesCartridgeHeader", 0);
		s.add(new ArrayDataType(new ByteDataType(), 21, 1), "title", "Cartridge title (ASCII)");
		s.add(new ByteDataType(), "mapMode", "Mapping mode (0x20 LoROM, 0x21 HiROM, 0x25 ExHiROM, +0x10 = FastROM)");
		s.add(new ByteDataType(), "cartridgeType", "ROM/RAM/SRAM/coprocessor flags");
		s.add(new ByteDataType(), "romSize", "log2(KiB)");
		s.add(new ByteDataType(), "ramSize", "SRAM log2(KiB), 0 = none");
		s.add(new ByteDataType(), "region", "Country / region code");
		s.add(new ByteDataType(), "developerId", "0x33 = extended header present at -0x10");
		s.add(new ByteDataType(), "version", "ROM version");
		s.add(new WordDataType(), "checksumComplement", "Checksum XOR'd with 0xFFFF");
		s.add(new WordDataType(), "checksum", "Checksum (sum + complement = 0xFFFF)");
		s.add(new ArrayDataType(new ByteDataType(), 4, 1), "_pad", "");
		// Native vectors at +0x24..0x2F
		s.add(new PointerDataType(WordDataType.dataType, 2), "nativeCop", "Native COP vector");
		s.add(new PointerDataType(WordDataType.dataType, 2), "nativeBrk", "Native BRK vector");
		s.add(new PointerDataType(WordDataType.dataType, 2), "nativeAbort", "Native ABORT vector");
		s.add(new PointerDataType(WordDataType.dataType, 2), "nativeNmi", "Native NMI vector");
		s.add(new WordDataType(), "_nativeReserved", "");
		s.add(new PointerDataType(WordDataType.dataType, 2), "nativeIrq", "Native IRQ vector");
		// Emulation vectors at +0x34..0x3F
		s.add(new PointerDataType(WordDataType.dataType, 2), "emuCop", "Emulation COP vector");
		s.add(new WordDataType(), "_emuReserved", "");
		s.add(new PointerDataType(WordDataType.dataType, 2), "emuAbort", "Emulation ABORT vector");
		s.add(new PointerDataType(WordDataType.dataType, 2), "emuNmi", "Emulation NMI vector");
		s.add(new PointerDataType(WordDataType.dataType, 2), "emuReset", "Emulation RESET vector");
		s.add(new PointerDataType(WordDataType.dataType, 2), "emuIrqBrk", "Emulation IRQ/BRK vector");

		Address hdr = bus.getAddress(CART_HEADER_ADDR_LOROM);
		try {
			MemoryBlock block = program.getMemory().getBlock(hdr);
			if (block == null) {
				return;
			}
			DataUtilities.createData(program, hdr, s, -1, ClearDataMode.CLEAR_ALL_CONFLICT_DATA);
			SymbolTable st = program.getSymbolTable();
			st.createLabel(hdr, "snesCartridgeHeader", SourceType.IMPORTED);
		}
		catch (Exception e) {
			log.appendException(e);
		}
	}

	/** Best-effort disassemble + create function helper. */
	public static void setFunction(FlatProgramAPI fpa, Address address, String name,
			boolean entryPoint, MessageLog log) {
		Program program = fpa.getCurrentProgram();
		try {
			SymbolTable st = program.getSymbolTable();
			if (program.getListing().getInstructionAt(address) == null) {
				new DisassembleCommand(address, null, true).applyTo(program, TaskMonitor.DUMMY);
			}
			new CreateFunctionCmd(name, address, null, SourceType.IMPORTED)
					.applyTo(program, TaskMonitor.DUMMY);
			if (entryPoint) {
				st.addExternalEntryPoint(address);
			}
			if (!st.hasSymbol(address)) {
				st.createLabel(address, name, SourceType.IMPORTED);
			}
		}
		catch (InvalidInputException e) {
			log.appendException(e);
		}
	}
}

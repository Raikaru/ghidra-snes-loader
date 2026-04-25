// SPDX-License-Identifier: MIT
package snesloader;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;

/**
 * Names for the SNES memory-mapped hardware registers. Anything labelled here
 * lives inside the {@code hwregs} block created by {@link SnesPostLoader}.
 *
 * <p>The list is intentionally exhaustive (PPU, APU, WRAM access, joypads,
 * legacy/auto-read joypads, multiplier/divider, IRQ timing, DMA channels) so
 * that disassembled SNES code shows symbolic register names instead of bare
 * addresses, mirroring what {@code lab313ru/ghidra_psx_ldr} does for the PSX
 * hardware register space.</p>
 */
public final class SnesHardware {

	private SnesHardware() {}

	/** A single named register: address and a short doc-comment for the listing. */
	private record Reg(long addr, String name, String comment) {}

	private static final Reg[] REGISTERS = new Reg[] {
		// --- PPU $2100-$213F -----------------------------------------------------
		new Reg(0x2100, "INIDISP", "Display control 1 (force blank, brightness)"),
		new Reg(0x2101, "OBSEL", "Object size & character base address"),
		new Reg(0x2102, "OAMADDL", "OAM address (low)"),
		new Reg(0x2103, "OAMADDH", "OAM address (high) / priority bit"),
		new Reg(0x2104, "OAMDATA", "OAM data write"),
		new Reg(0x2105, "BGMODE", "BG mode and BG character size"),
		new Reg(0x2106, "MOSAIC", "Mosaic size & enable"),
		new Reg(0x2107, "BG1SC", "BG1 tilemap address & screen size"),
		new Reg(0x2108, "BG2SC", "BG2 tilemap address & screen size"),
		new Reg(0x2109, "BG3SC", "BG3 tilemap address & screen size"),
		new Reg(0x210A, "BG4SC", "BG4 tilemap address & screen size"),
		new Reg(0x210B, "BG12NBA", "BG1/BG2 tile base address"),
		new Reg(0x210C, "BG34NBA", "BG3/BG4 tile base address"),
		new Reg(0x210D, "BG1HOFS", "BG1 horizontal scroll / mode-7 H-scroll"),
		new Reg(0x210E, "BG1VOFS", "BG1 vertical scroll / mode-7 V-scroll"),
		new Reg(0x210F, "BG2HOFS", "BG2 horizontal scroll"),
		new Reg(0x2110, "BG2VOFS", "BG2 vertical scroll"),
		new Reg(0x2111, "BG3HOFS", "BG3 horizontal scroll"),
		new Reg(0x2112, "BG3VOFS", "BG3 vertical scroll"),
		new Reg(0x2113, "BG4HOFS", "BG4 horizontal scroll"),
		new Reg(0x2114, "BG4VOFS", "BG4 vertical scroll"),
		new Reg(0x2115, "VMAIN", "Video port control (VRAM increment mode)"),
		new Reg(0x2116, "VMADDL", "VRAM address (low)"),
		new Reg(0x2117, "VMADDH", "VRAM address (high)"),
		new Reg(0x2118, "VMDATAL", "VRAM data write (low)"),
		new Reg(0x2119, "VMDATAH", "VRAM data write (high)"),
		new Reg(0x211A, "M7SEL", "Mode-7 settings"),
		new Reg(0x211B, "M7A", "Mode-7 matrix A (also multiplicand)"),
		new Reg(0x211C, "M7B", "Mode-7 matrix B (also multiplier)"),
		new Reg(0x211D, "M7C", "Mode-7 matrix C"),
		new Reg(0x211E, "M7D", "Mode-7 matrix D"),
		new Reg(0x211F, "M7X", "Mode-7 center X"),
		new Reg(0x2120, "M7Y", "Mode-7 center Y"),
		new Reg(0x2121, "CGADD", "CGRAM address"),
		new Reg(0x2122, "CGDATA", "CGRAM data write"),
		new Reg(0x2123, "W12SEL", "Window mask settings BG1 / BG2"),
		new Reg(0x2124, "W34SEL", "Window mask settings BG3 / BG4"),
		new Reg(0x2125, "WOBJSEL", "Window mask settings OBJ / colour"),
		new Reg(0x2126, "WH0", "Window 1 left position"),
		new Reg(0x2127, "WH1", "Window 1 right position"),
		new Reg(0x2128, "WH2", "Window 2 left position"),
		new Reg(0x2129, "WH3", "Window 2 right position"),
		new Reg(0x212A, "WBGLOG", "Window mask logic for BGs"),
		new Reg(0x212B, "WOBJLOG", "Window mask logic for OBJ / colour"),
		new Reg(0x212C, "TM", "Main screen designation"),
		new Reg(0x212D, "TS", "Sub screen designation"),
		new Reg(0x212E, "TMW", "Window mask main screen"),
		new Reg(0x212F, "TSW", "Window mask sub screen"),
		new Reg(0x2130, "CGWSEL", "Color math control register A"),
		new Reg(0x2131, "CGADSUB", "Color math control register B"),
		new Reg(0x2132, "COLDATA", "Color math sub screen backdrop colour"),
		new Reg(0x2133, "SETINI", "Display control 2 (interlace, overscan, ...)"),
		new Reg(0x2134, "MPYL", "PPU multiplication result (low)"),
		new Reg(0x2135, "MPYM", "PPU multiplication result (mid)"),
		new Reg(0x2136, "MPYH", "PPU multiplication result (high)"),
		new Reg(0x2137, "SLHV", "Software latch for H/V counter"),
		new Reg(0x2138, "OAMDATAREAD", "OAM data read"),
		new Reg(0x2139, "VMDATALREAD", "VRAM data read (low)"),
		new Reg(0x213A, "VMDATAHREAD", "VRAM data read (high)"),
		new Reg(0x213B, "CGDATAREAD", "CGRAM data read"),
		new Reg(0x213C, "OPHCT", "Horizontal counter latch"),
		new Reg(0x213D, "OPVCT", "Vertical counter latch"),
		new Reg(0x213E, "STAT77", "PPU1 status"),
		new Reg(0x213F, "STAT78", "PPU2 status / open bus / version"),

		// --- APU I/O ports $2140-$2143 (mirrored every 4 bytes up to $217F) -----
		new Reg(0x2140, "APUI00", "APU I/O port 0"),
		new Reg(0x2141, "APUI01", "APU I/O port 1"),
		new Reg(0x2142, "APUI02", "APU I/O port 2"),
		new Reg(0x2143, "APUI03", "APU I/O port 3"),

		// --- WRAM access via $2180-$2183 ----------------------------------------
		new Reg(0x2180, "WMDATA", "WRAM data port (read/write)"),
		new Reg(0x2181, "WMADDL", "WRAM address (low)"),
		new Reg(0x2182, "WMADDM", "WRAM address (mid)"),
		new Reg(0x2183, "WMADDH", "WRAM address (high)"),

		// --- Manual joypad (legacy controller serial port) ----------------------
		new Reg(0x4016, "JOYSER0", "Joypad serial port 1 (latch on write, data on read)"),
		new Reg(0x4017, "JOYSER1", "Joypad serial port 2"),

		// --- CPU registers $4200-$421F ------------------------------------------
		new Reg(0x4200, "NMITIMEN", "Interrupt enable & joypad auto-read enable"),
		new Reg(0x4201, "WRIO", "Programmable I/O port (out)"),
		new Reg(0x4202, "WRMPYA", "Multiplicand A"),
		new Reg(0x4203, "WRMPYB", "Multiplicand B (writing here triggers the mult)"),
		new Reg(0x4204, "WRDIVL", "Dividend (low)"),
		new Reg(0x4205, "WRDIVH", "Dividend (high)"),
		new Reg(0x4206, "WRDIVB", "Divisor (writing here triggers the divide)"),
		new Reg(0x4207, "HTIMEL", "H-IRQ counter target (low)"),
		new Reg(0x4208, "HTIMEH", "H-IRQ counter target (high)"),
		new Reg(0x4209, "VTIMEL", "V-IRQ counter target (low)"),
		new Reg(0x420A, "VTIMEH", "V-IRQ counter target (high)"),
		new Reg(0x420B, "MDMAEN", "DMA channel enable (1 byte = 1 channel)"),
		new Reg(0x420C, "HDMAEN", "HDMA channel enable"),
		new Reg(0x420D, "MEMSEL", "ROM access speed (FastROM bit)"),
		new Reg(0x4210, "RDNMI", "NMI flag & 5A22 version"),
		new Reg(0x4211, "TIMEUP", "IRQ flag (read clears)"),
		new Reg(0x4212, "HVBJOY", "PPU status / joypad auto-read busy"),
		new Reg(0x4213, "RDIO", "Programmable I/O port (in)"),
		new Reg(0x4214, "RDDIVL", "Quotient of last divide (low)"),
		new Reg(0x4215, "RDDIVH", "Quotient of last divide (high)"),
		new Reg(0x4216, "RDMPYL", "Result of last multiply / remainder (low)"),
		new Reg(0x4217, "RDMPYH", "Result of last multiply / remainder (high)"),
		new Reg(0x4218, "JOY1L", "Auto-read joypad 1 (low)"),
		new Reg(0x4219, "JOY1H", "Auto-read joypad 1 (high)"),
		new Reg(0x421A, "JOY2L", "Auto-read joypad 2 (low)"),
		new Reg(0x421B, "JOY2H", "Auto-read joypad 2 (high)"),
		new Reg(0x421C, "JOY3L", "Auto-read joypad 3 (low)"),
		new Reg(0x421D, "JOY3H", "Auto-read joypad 3 (high)"),
		new Reg(0x421E, "JOY4L", "Auto-read joypad 4 (low)"),
		new Reg(0x421F, "JOY4H", "Auto-read joypad 4 (high)"),
	};

	/** DMA channel base addresses, $43x0..$43xF, x=0..7. */
	private static final String[] DMA_PER_CHANNEL_NAMES = new String[] {
		"DMAP", "BBAD", "A1TL", "A1TH", "A1B",
		"DASL", "DASH", "DASB",
		"A2AL", "A2AH",
		"NTRL"
	};

	private static final String[] DMA_PER_CHANNEL_COMMENTS = new String[] {
		"DMA control / direction", "B-bus destination ($21xx)",
		"DMA source A1 (low)", "DMA source A1 (high)", "DMA source A1 (bank)",
		"DMA size / HDMA indirect (low)", "DMA size / HDMA indirect (high)",
		"DMA size / HDMA indirect (bank)",
		"HDMA table addr (low)", "HDMA table addr (high)",
		"HDMA line counter"
	};

	public static void applyLabels(FlatProgramAPI fpa, MessageLog log) {
		for (Reg r : REGISTERS) {
			labelByte(fpa, r.addr, r.name, r.comment, log);
		}
		// DMA channels at $4300..$437F (8 channels * $10 stride)
		for (int ch = 0; ch < 8; ch++) {
			long base = 0x4300L + (long) ch * 0x10L;
			for (int i = 0; i < DMA_PER_CHANNEL_NAMES.length; i++) {
				labelByte(fpa, base + i,
					String.format("%s%d", DMA_PER_CHANNEL_NAMES[i], ch),
					String.format("DMA channel %d: %s", ch, DMA_PER_CHANNEL_COMMENTS[i]),
					log);
			}
		}
	}

	private static void labelByte(FlatProgramAPI fpa, long offset, String name, String comment,
			MessageLog log) {
		Address addr = fpa.getCurrentProgram().getAddressFactory()
				.getDefaultAddressSpace().getAddress(offset);
		try {
			fpa.createByte(addr);
		}
		catch (Exception ignored) {
			// Cell may already be defined by another labelling pass; that's fine.
		}
		try {
			SymbolTable st = fpa.getCurrentProgram().getSymbolTable();
			st.createLabel(addr, name, SourceType.IMPORTED);
			if (comment != null && !comment.isEmpty()) {
				fpa.setEOLComment(addr, comment);
			}
		}
		catch (InvalidInputException e) {
			log.appendException(e);
		}
	}
}

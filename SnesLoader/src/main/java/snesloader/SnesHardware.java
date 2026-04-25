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

	/**
	 * Banks where the SNES CPU bus exposes the hardware-register window
	 * (and LowRAM mirror). Used by {@link #applyLabels} when label mirroring
	 * is enabled so e.g. {@code STA $4200} from a PHK/PLB function in bank
	 * {@code $80} resolves to {@code NMITIMEN} instead of a bare address.
	 *
	 * <p>The list is intentionally non-contiguous: it skips $40-$7D (HiROM
	 * full-bank ROM mirror) and $7E-$7F (WRAM), where the CPU bus does not
	 * expose the I/O window.</p>
	 */
	private static final int[] LABEL_MIRROR_BANK_RANGES = {
		0x00, 0x3F,
		0x80, 0xBF
	};

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
		applyLabels(fpa, log, false);
	}

	/**
	 * Apply the canonical hardware-register labels at bank {@code $00}.
	 *
	 * @param mirrorAcrossBanks
	 *            when {@code true}, also place the same labels at every bank
	 *            in {@code $00-$3F} and {@code $80-$BF} so that decompiled
	 *            code running with a non-zero DBR (typical after
	 *            {@code PHK ; PLB}) shows symbolic register names rather
	 *            than bare 24-bit addresses. Off by default to keep
	 *            symbol-table size manageable on small projects.
	 */
	public static void applyLabels(FlatProgramAPI fpa, MessageLog log, boolean mirrorAcrossBanks) {
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
		if (mirrorAcrossBanks) {
			mirrorLabelsAcrossBanks(fpa, log);
		}
	}

	/**
	 * Walk every byte-mapped {@code lowram_mirror_BB} / {@code hwregs_mirror_BB}
	 * bank and copy each canonical hardware-register label to the same
	 * offset in that bank. The decompiler keys symbol lookup on the
	 * absolute address, so without this {@code STA $4200} from a function
	 * with {@code DBR=$80} renders as {@code (*(byte*)0x80004200) = ...}.
	 */
	private static void mirrorLabelsAcrossBanks(FlatProgramAPI fpa, MessageLog log) {
		for (int range = 0; range < LABEL_MIRROR_BANK_RANGES.length; range += 2) {
			int lo = LABEL_MIRROR_BANK_RANGES[range];
			int hi = LABEL_MIRROR_BANK_RANGES[range + 1];
			for (int bank = lo; bank <= hi; bank++) {
				if (bank == 0) continue; // canonical pass already labelled $00
				long bankBase = ((long) bank) << 16;
				for (Reg r : REGISTERS) {
					labelOnly(fpa, bankBase | r.addr, r.name, log);
				}
				for (int ch = 0; ch < 8; ch++) {
					long base = 0x4300L + (long) ch * 0x10L;
					for (int i = 0; i < DMA_PER_CHANNEL_NAMES.length; i++) {
						labelOnly(fpa, bankBase | (base + i),
							String.format("%s%d", DMA_PER_CHANNEL_NAMES[i], ch), log);
					}
				}
			}
		}
	}

	/** MSU-1 audio/data streaming register window ($00:2000..$00:2007). */
	private static final Reg[] MSU1_REGISTERS = new Reg[] {
		new Reg(0x2000, "MSU_STATUS", "MSU-1 status (audio busy/data busy/track missing/...)"),
		new Reg(0x2001, "MSU_READ", "MSU-1 data read port"),
		new Reg(0x2002, "MSU_ID0", "MSU-1 identifier byte 0 (read returns 'S')"),
		new Reg(0x2003, "MSU_ID1", "MSU-1 identifier byte 1 (read returns '-')"),
		new Reg(0x2004, "MSU_ID2", "MSU-1 identifier byte 2 (read returns 'M')"),
		new Reg(0x2005, "MSU_ID3", "MSU-1 identifier byte 3 (read returns 'S')"),
		new Reg(0x2006, "MSU_ID4", "MSU-1 identifier byte 4 (read returns 'U')"),
		new Reg(0x2007, "MSU_ID5", "MSU-1 identifier byte 5 (read returns '1')"),

		new Reg(0x2000, "MSU_DATA_SEEK_LOW",  "MSU-1 data seek address (low) [write]"),
		new Reg(0x2001, "MSU_DATA_SEEK_MID",  "MSU-1 data seek address (mid) [write]"),
		new Reg(0x2002, "MSU_DATA_SEEK_HIGH", "MSU-1 data seek address (high) [write]"),
		new Reg(0x2003, "MSU_DATA_SEEK_TOP",  "MSU-1 data seek address (top) [write]"),
		new Reg(0x2004, "MSU_AUDIO_TRACK_LO", "MSU-1 audio track (low) [write]"),
		new Reg(0x2005, "MSU_AUDIO_TRACK_HI", "MSU-1 audio track (high) [write]"),
		new Reg(0x2006, "MSU_AUDIO_VOLUME",   "MSU-1 audio volume [write]"),
		new Reg(0x2007, "MSU_AUDIO_CONTROL",  "MSU-1 audio control (play/repeat/resume) [write]"),
	};

	/** SA-1 coprocessor register window (complete; $00:2200..$00:230E). */
	private static final Reg[] SA1_REGISTERS = new Reg[] {
		new Reg(0x2200, "SA1_CCNT",  "SA-1 control / SNES->SA-1 message"),
		new Reg(0x2201, "SA1_SIE",   "SNES interrupt enable"),
		new Reg(0x2202, "SA1_SIC",   "SNES interrupt clear"),
		new Reg(0x2203, "SA1_CRV_L", "SA-1 CPU reset vector (low)"),
		new Reg(0x2204, "SA1_CRV_H", "SA-1 CPU reset vector (high)"),
		new Reg(0x2205, "SA1_CNV_L", "SA-1 CPU NMI vector (low)"),
		new Reg(0x2206, "SA1_CNV_H", "SA-1 CPU NMI vector (high)"),
		new Reg(0x2207, "SA1_CIV_L", "SA-1 CPU IRQ vector (low)"),
		new Reg(0x2208, "SA1_CIV_H", "SA-1 CPU IRQ vector (high)"),
		new Reg(0x2209, "SA1_SCNT",  "SA-1 status / SA-1->SNES message"),
		new Reg(0x220A, "SA1_CIE",   "SA-1 interrupt enable"),
		new Reg(0x220B, "SA1_CIC",   "SA-1 interrupt clear"),
		new Reg(0x220C, "SA1_SNV_L", "SNES NMI vector (low)"),
		new Reg(0x220D, "SA1_SNV_H", "SNES NMI vector (high)"),
		new Reg(0x220E, "SA1_SIV_L", "SNES IRQ vector (low)"),
		new Reg(0x220F, "SA1_SIV_H", "SNES IRQ vector (high)"),
		// Timer control and HDMA timer registers
		new Reg(0x2210, "SA1_SCNT",   "SA-1 timer restart control [write]"),
		new Reg(0x2211, "SA1_STRV",   "SA-1 timer restart value [write]"),
		new Reg(0x2212, "SA1_HCNT_L", "SA-1 HDMA timer count (low)"),
		new Reg(0x2213, "SA1_HCNT_H", "SA-1 HDMA timer count (high)"),
		// Super MMC bank registers
		new Reg(0x2220, "SA1_CXB",   "Super MMC bank for $C0-$CF"),
		new Reg(0x2221, "SA1_DXB",   "Super MMC bank for $D0-$DF"),
		new Reg(0x2222, "SA1_EXB",   "Super MMC bank for $E0-$EF"),
		new Reg(0x2223, "SA1_FXB",   "Super MMC bank for $F0-$FF"),
		new Reg(0x2224, "SA1_BMAPS", "SA-1 BW-RAM bank for SNES"),
		new Reg(0x2225, "SA1_BMAP",  "SA-1 BW-RAM bank for SA-1"),
		new Reg(0x2226, "SA1_SBWE",  "SNES BW-RAM write enable"),
		new Reg(0x2227, "SA1_CBWE",  "SA-1 BW-RAM write enable"),
		new Reg(0x2228, "SA1_BWPA",  "BW-RAM write protection size"),
		new Reg(0x2229, "SA1_SIWP",  "SNES IWRAM write enable"),
		new Reg(0x222A, "SA1_CIWP",  "SA-1 IWRAM write enable"),
		// DMA / character conversion registers
		new Reg(0x2230, "SA1_DMACR", "SA-1 DMA control"),
		new Reg(0x2231, "SA1_DMACB_L","SA-1 DMA byte count (low)"),
		new Reg(0x2232, "SA1_DMACB_H","SA-1 DMA byte count (high)"),
		new Reg(0x2233, "SA1_DMADA_L","SA-1 DMA source address (low)"),
		new Reg(0x2234, "SA1_DMADA_M","SA-1 DMA source address (mid)"),
		new Reg(0x2235, "SA1_DMADA_H","SA-1 DMA source address (high)"),
		new Reg(0x2236, "SA1_DMASA_L","SA-1 DMA dest address (low)"),
		new Reg(0x2237, "SA1_DMASA_M","SA-1 DMA dest address (mid)"),
		new Reg(0x2238, "SA1_DMASA_H","SA-1 DMA dest address (high)"),
		new Reg(0x2239, "SA1_CHNEN_L","SA-1 character conversion param (low)"),
		new Reg(0x223A, "SA1_CHNEN_H","SA-1 character conversion param (high)"),
		new Reg(0x223B, "SA1_CHNCV_L","SA-1 character conversion value (low)"),
		new Reg(0x223C, "SA1_CHNCV_M","SA-1 character conversion value (mid)"),
		new Reg(0x223D, "SA1_CHNCV_H","SA-1 character conversion value (high)"),
		new Reg(0x223F, "SA1_CHCFG",  "SA-1 character conversion config / status"),
		// Bitmap register file
		new Reg(0x2240, "SA1_BMAP0_L","SA-1 bitmap register 0 (low)"),
		new Reg(0x2241, "SA1_BMAP0_H","SA-1 bitmap register 0 (high)"),
		new Reg(0x2242, "SA1_BMAP1_L","SA-1 bitmap register 1 (low)"),
		new Reg(0x2243, "SA1_BMAP1_H","SA-1 bitmap register 1 (high)"),
		new Reg(0x2244, "SA1_BMAP2_L","SA-1 bitmap register 2 (low)"),
		new Reg(0x2245, "SA1_BMAP2_H","SA-1 bitmap register 2 (high)"),
		new Reg(0x2246, "SA1_BMAP3_L","SA-1 bitmap register 3 (low)"),
		new Reg(0x2247, "SA1_BMAP3_H","SA-1 bitmap register 3 (high)"),
		new Reg(0x2248, "SA1_BMAP4_L","SA-1 bitmap register 4 (low)"),
		new Reg(0x2249, "SA1_BMAP4_H","SA-1 bitmap register 4 (high)"),
		new Reg(0x224A, "SA1_BMAP5_L","SA-1 bitmap register 5 (low)"),
		new Reg(0x224B, "SA1_BMAP5_H","SA-1 bitmap register 5 (high)"),
		new Reg(0x224C, "SA1_BMAP6_L","SA-1 bitmap register 6 (low)"),
		new Reg(0x224D, "SA1_BMAP6_H","SA-1 bitmap register 6 (high)"),
		new Reg(0x224E, "SA1_BMAP7_L","SA-1 bitmap register 7 (low)"),
		new Reg(0x224F, "SA1_BMAP7_H","SA-1 bitmap register 7 (high)"),
		// Arithmetic registers
		new Reg(0x2250, "SA1_MPB_L",  "SA-1 multiply / divide param B (low)"),
		new Reg(0x2251, "SA1_MPB_H",  "SA-1 multiply / divide param B (high)"),
		new Reg(0x2252, "SA1_MPB_B",  "SA-1 multiply / divide param B (bank)"),
		new Reg(0x2253, "SA1_MRA_L",  "SA-1 multiply / divide param A (low) / result (low)"),
		new Reg(0x2254, "SA1_MRA_H",  "SA-1 multiply / divide param A (high) / result (mid)"),
		new Reg(0x2255, "SA1_MRA_B",  "SA-1 multiply / divide param A (bank) / result (high)"),
		new Reg(0x2258, "SA1_VBP",    "SA-1 variable-length bit processing"),
		new Reg(0x2259, "SA1_VBIT",   "SA-1 variable-length bit position"),
		new Reg(0x225A, "SA1_VBUP_L", "SA-1 variable-length bit upper (low)"),
		new Reg(0x225B, "SA1_VBUP_H", "SA-1 variable-length bit upper (high)"),
		// Result / status registers
		new Reg(0x2300, "SA1_DAP_L",  "SA-1 DMA parameter (low) [read]"),
		new Reg(0x2301, "SA1_DAP_H",  "SA-1 DMA parameter (high) [read]"),
		new Reg(0x2302, "SA1_DAP_B",  "SA-1 DMA parameter (bank) [read]"),
		new Reg(0x2303, "SA1_DTC_L",  "SA-1 DMA byte count [read]"),
		new Reg(0x2304, "SA1_DTC_H",  "SA-1 DMA byte count (high) [read]"),
		new Reg(0x2305, "SA1_CCR_L",  "SA-1 character conversion result (low) [read]"),
		new Reg(0x2306, "SA1_CCR_H",  "SA-1 character conversion result (high) [read]"),
		new Reg(0x2307, "SA1_CCR_B",  "SA-1 character conversion result (bank) [read]"),
		new Reg(0x2308, "SA1_MDR_L",  "SA-1 multiply / divide result (low) [read]"),
		new Reg(0x2309, "SA1_MDR_M",  "SA-1 multiply / divide result (mid) [read]"),
		new Reg(0x230A, "SA1_MDR_H",  "SA-1 multiply / divide result (high) [read]"),
		new Reg(0x230B, "SA1_OMDR_L", "SA-1 old multiply / divide result (low) [read]"),
		new Reg(0x230C, "SA1_OMDR_H", "SA-1 old multiply / divide result (high) [read]"),
		new Reg(0x230D, "SA1_VBD_L",  "SA-1 variable-length bit data (low) [read]"),
		new Reg(0x230E, "SA1_VBD_H",  "SA-1 variable-length bit data (high) [read]"),
	};

	/** SuperFX (GSU-1/2) coprocessor register window (subset; $00:3000..$00:32FF). */
	private static final Reg[] GSU_REGISTERS = new Reg[] {
		new Reg(0x3030, "GSU_SFR",  "GSU status / flag register (low)"),
		new Reg(0x3031, "GSU_SFRH", "GSU status / flag register (high)"),
		new Reg(0x3033, "GSU_BRAMR","GSU backup-RAM enable"),
		new Reg(0x3034, "GSU_PBR",  "GSU program bank"),
		new Reg(0x3036, "GSU_ROMBR","GSU ROM bank"),
		new Reg(0x3037, "GSU_CFGR", "GSU config / IRQ"),
		new Reg(0x3038, "GSU_SCBR", "GSU screen base"),
		new Reg(0x3039, "GSU_CLSR", "GSU clock select"),
		new Reg(0x303A, "GSU_SCMR", "GSU screen mode"),
		new Reg(0x303B, "GSU_VCR",  "GSU version code (read-only)"),
		new Reg(0x303C, "GSU_RAMBR","GSU RAM bank"),
		new Reg(0x303E, "GSU_CBR_L","GSU cache base (low)"),
		new Reg(0x303F, "GSU_CBR_H","GSU cache base (high)"),
	};

	/** S-DD1 register window ($00:4800..$00:480F). */
	private static final Reg[] SDD1_REGISTERS = new Reg[] {
		new Reg(0x4800, "SDD1_DMA_TRIGGER", "S-DD1 DMA trigger (write to start a transfer)"),
		new Reg(0x4801, "SDD1_DMA_ENABLE", "S-DD1 DMA enable mask"),
		new Reg(0x4804, "SDD1_MMC0", "S-DD1 MMC bank for $C0-$CF"),
		new Reg(0x4805, "SDD1_MMC1", "S-DD1 MMC bank for $D0-$DF"),
		new Reg(0x4806, "SDD1_MMC2", "S-DD1 MMC bank for $E0-$EF"),
		new Reg(0x4807, "SDD1_MMC3", "S-DD1 MMC bank for $F0-$FF"),
	};

	/** Cx4 (Hitachi SH-1 custom) register window ($00:7F40..$00:7FAF). */
	private static final Reg[] CX4_REGISTERS = new Reg[] {
		new Reg(0x7F40, "CX4_BUSY",   "Cx4 busy flag / status"),
		new Reg(0x7F42, "CX4_CMD",    "Cx4 command (triggers processing)"),
		new Reg(0x7F44, "CX4_PRM0_L", "Cx4 parameter 0 (low)"),
		new Reg(0x7F45, "CX4_PRM0_H", "Cx4 parameter 0 (high)"),
		new Reg(0x7F46, "CX4_PRM1_L", "Cx4 parameter 1 (low)"),
		new Reg(0x7F47, "CX4_PRM1_H", "Cx4 parameter 1 (high)"),
		new Reg(0x7F48, "CX4_PRM2_L", "Cx4 parameter 2 (low)"),
		new Reg(0x7F49, "CX4_PRM2_H", "Cx4 parameter 2 (high)"),
		new Reg(0x7F4A, "CX4_PRM3_L", "Cx4 parameter 3 (low)"),
		new Reg(0x7F4B, "CX4_PRM3_H", "Cx4 parameter 3 (high)"),
		new Reg(0x7F4C, "CX4_PRM4_L", "Cx4 parameter 4 (low)"),
		new Reg(0x7F4D, "CX4_PRM4_H", "Cx4 parameter 4 (high)"),
		new Reg(0x7F4E, "CX4_RES6_L", "Cx4 result 6 (low)"),
		new Reg(0x7F4F, "CX4_PTR",    "Cx4 command / instruction pointer"),
		new Reg(0x7F50, "CX4_PRM6_L", "Cx4 parameter 6 (low)"),
		new Reg(0x7F51, "CX4_PRM6_H", "Cx4 parameter 6 (high)"),
		new Reg(0x7F52, "CX4_PRM7_L", "Cx4 parameter 7 (low)"),
		new Reg(0x7F53, "CX4_PRM7_H", "Cx4 parameter 7 (high)"),
		new Reg(0x7F54, "CX4_RES0_L", "Cx4 result 0 (low)"),
		new Reg(0x7F55, "CX4_RES0_H", "Cx4 result 0 (high)"),
		new Reg(0x7F56, "CX4_RES1_L", "Cx4 result 1 (low)"),
		new Reg(0x7F57, "CX4_RES1_H", "Cx4 result 1 (high)"),
		new Reg(0x7F58, "CX4_RES2_L", "Cx4 result 2 (low)"),
		new Reg(0x7F59, "CX4_RES2_H", "Cx4 result 2 (high)"),
		new Reg(0x7F5A, "CX4_RES3_L", "Cx4 result 3 (low)"),
		new Reg(0x7F5B, "CX4_RES3_H", "Cx4 result 3 (high)"),
		new Reg(0x7F5C, "CX4_RES4_L", "Cx4 result 4 (low)"),
		new Reg(0x7F5D, "CX4_RES4_H", "Cx4 result 4 (high)"),
		new Reg(0x7F5E, "CX4_RES5_L", "Cx4 result 5 (low)"),
		new Reg(0x7F5F, "CX4_RES5_H", "Cx4 result 5 (high)"),
		new Reg(0x7F60, "CX4_RES6_L", "Cx4 result 6 (low)"),
		new Reg(0x7F61, "CX4_RES6_H", "Cx4 result 6 (high)"),
		new Reg(0x7F62, "CX4_RES7_L", "Cx4 result 7 (low)"),
		new Reg(0x7F63, "CX4_RES7_H", "Cx4 result 7 (high)"),
		// General-purpose register file ($7F80-$7FAF, 16 x 3 bytes)
		new Reg(0x7F80, "CX4_REG0",   "Cx4 register 0"),
		new Reg(0x7F81, "CX4_REG1",   "Cx4 register 1"),
		new Reg(0x7F82, "CX4_REG2",   "Cx4 register 2"),
		new Reg(0x7F83, "CX4_REG3",   "Cx4 register 3"),
		new Reg(0x7F84, "CX4_REG4",   "Cx4 register 4"),
		new Reg(0x7F85, "CX4_REG5",   "Cx4 register 5"),
		new Reg(0x7F86, "CX4_REG6",   "Cx4 register 6"),
		new Reg(0x7F87, "CX4_REG7",   "Cx4 register 7"),
		new Reg(0x7F88, "CX4_REG8",   "Cx4 register 8"),
		new Reg(0x7F89, "CX4_REG9",   "Cx4 register 9"),
		new Reg(0x7F8A, "CX4_REGA",   "Cx4 register 10"),
		new Reg(0x7F8B, "CX4_REGB",   "Cx4 register 11"),
		new Reg(0x7F8C, "CX4_REGC",   "Cx4 register 12"),
		new Reg(0x7F8D, "CX4_REGD",   "Cx4 register 13"),
		new Reg(0x7F8E, "CX4_REGE",   "Cx4 register 14"),
		new Reg(0x7F8F, "CX4_REGF",   "Cx4 register 15"),
	};
	/** S-RTC register window ($00:2800..$00:2801). */
	private static final Reg[] SRTC_REGISTERS = new Reg[] {
		new Reg(0x2800, "SRTC_CMD",  "S-RTC command / status"),
		new Reg(0x2801, "SRTC_DATA", "S-RTC data port"),
	};

	/** OBC-1 register window ($00:7FF0..$00:7FF7). */
	private static final Reg[] OBC1_REGISTERS = new Reg[] {
		new Reg(0x7FF0, "OBC1_CTRL", "OBC-1 control"),
		new Reg(0x7FF1, "OBC1_DATA", "OBC-1 data"),
	};

	/** SPC7110 extended registers ($00:4810..$00:483F). MMC at $4800-$4807. */
	private static final Reg[] SPC7110_REGISTERS = new Reg[] {
		new Reg(0x4810, "SPC7110_DATA",   "SPC7110 data port"),
		new Reg(0x4811, "SPC7110_ADDR0",  "SPC7110 address (low)"),
		new Reg(0x4812, "SPC7110_ADDR1",  "SPC7110 address (mid)"),
		new Reg(0x4813, "SPC7110_ADDR2",  "SPC7110 address (high)"),
		new Reg(0x4814, "SPC7110_CTRL",   "SPC7110 control / status"),
	};

	/** ST018 register window ($00:3800..$00:3804). */
	private static final Reg[] ST018_REGISTERS = new Reg[] {
		new Reg(0x3800, "ST018_CMD0",  "ST018 command 0"),
		new Reg(0x3801, "ST018_CMD1",  "ST018 command 1"),
		new Reg(0x3802, "ST018_CMD2",  "ST018 command 2"),
		new Reg(0x3803, "ST018_CMD3",  "ST018 command 3"),
		new Reg(0x3804, "ST018_STATUS","ST018 status"),
	};

	/**
	 * Apply optional coprocessor-specific labels for chips advertised in the
	 * cartridge header. Safe to call on any ROM; chips that aren't present
	 * just produce no extra labels.
	 */
	public static void applyCoprocessorLabels(FlatProgramAPI fpa, SnesHeader.Coprocessor cp,
		MessageLog log) {
		if (cp == null || !cp.isPresent()) return;
		switch (cp) {
			case SA1:
				for (Reg r : SA1_REGISTERS) labelByte(fpa, r.addr, r.name, r.comment, log);
				break;
			case GSU:
				for (Reg r : GSU_REGISTERS) labelByte(fpa, r.addr, r.name, r.comment, log);
				break;
			case SDD1:
				for (Reg r : SDD1_REGISTERS) labelByte(fpa, r.addr, r.name, r.comment, log);
				break;
			case CUSTOM_CX4:
				for (Reg r : CX4_REGISTERS) labelByte(fpa, r.addr, r.name, r.comment, log);
				break;
			case SRTC:
				for (Reg r : SRTC_REGISTERS) labelByte(fpa, r.addr, r.name, r.comment, log);
				break;
			case CUSTOM_SPC7110:
				for (Reg r : SPC7110_REGISTERS) labelByte(fpa, r.addr, r.name, r.comment, log);
				break;
			case CUSTOM_ST018:
				for (Reg r : ST018_REGISTERS) labelByte(fpa, r.addr, r.name, r.comment, log);
				break;
			case OBC1:
				for (Reg r : OBC1_REGISTERS) labelByte(fpa, r.addr, r.name, r.comment, log);
				break;
			default:
				break;
		}
	}

	/**
	 * Apply MSU-1 register labels at $00:2000..$00:2007. Most homebrew
	 * targeting MSU-1 tests these registers explicitly so they're easy to
	 * spot in disassembly even when the cartridge header doesn't advertise
	 * the chip.
	 */
	public static void applyMsu1Labels(FlatProgramAPI fpa, MessageLog log) {
		for (Reg r : MSU1_REGISTERS) {
			labelByte(fpa, r.addr, r.name, r.comment, log);
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

	/**
	 * Like {@link #labelByte} but cheaper: only attaches the symbol, no
	 * data type or EOL comment. Used by {@link #mirrorLabelsAcrossBanks}
	 * where adding a {@code byte} data type at every mirror would force
	 * Ghidra to redundantly type tens of thousands of cells.
	 */
	private static void labelOnly(FlatProgramAPI fpa, long offset, String name, MessageLog log) {
		Address addr = fpa.getCurrentProgram().getAddressFactory()
				.getDefaultAddressSpace().getAddress(offset);
		try {
			SymbolTable st = fpa.getCurrentProgram().getSymbolTable();
			st.createLabel(addr, name, SourceType.IMPORTED);
		}
		catch (InvalidInputException e) {
			log.appendException(e);
		}
	}
}

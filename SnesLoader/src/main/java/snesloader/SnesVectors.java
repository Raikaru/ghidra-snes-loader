// SPDX-License-Identifier: MIT
package snesloader;

import java.math.BigInteger;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.flatapi.FlatProgramAPI;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.InvalidInputException;

/**
 * Annotates the 65816 native-mode and emulation-mode interrupt vector tables
 * located at the end of bank $00, and turns the targets into named functions.
 *
 * <p>Vector layout (relative to $00:0000):</p>
 * <pre>
 *   $FFE4 native COP        $FFE6 native BRK     $FFE8 native ABORT
 *   $FFEA native NMI        $FFEC reserved       $FFEE native IRQ
 *   $FFF4 emu  COP          $FFF6 reserved       $FFF8 emu  ABORT
 *   $FFFA emu  NMI          $FFFC emu  RESET     $FFFE emu  IRQ/BRK
 * </pre>
 */
public final class SnesVectors {

	private SnesVectors() {}

	/**
	 * Per-vector context override.
	 *
	 * <p>{@link Mode#EMULATION} sets the post-reset state ({@code E=M=X=1}).
	 * {@link Mode#NATIVE} sets {@code E=0, M=0, X=0} which matches the typical
	 * entry state of native NMI/IRQ handlers on SNES games — they re-enter in
	 * 16-bit accumulator/index mode and explicitly downsize with {@code SEP}
	 * if needed. Handlers that prefer a different convention can override
	 * the context per-function in the GUI.</p>
	 */
	private enum Mode { EMULATION, NATIVE }

	private record Vec(long addr, String name, String comment, boolean entry, Mode mode) {}

	private static final Vec[] VECTORS = new Vec[] {
		// Reset first so its target wins the function name when several vectors
		// share an entry point (very common in homebrew / minimal demos).
		new Vec(0xFFFCL, "vector_RESET", "Reset vector — entry point", true, Mode.EMULATION),
		// Native vectors at $FFE4..$FFEF
		new Vec(0xFFE4L, "vector_COP_native", "Native-mode COP vector", false, Mode.NATIVE),
		new Vec(0xFFE6L, "vector_BRK_native", "Native-mode BRK vector", false, Mode.NATIVE),
		new Vec(0xFFE8L, "vector_ABORT_native", "Native-mode ABORT vector", false, Mode.NATIVE),
		new Vec(0xFFEAL, "vector_NMI_native", "Native-mode NMI vector (V-blank)", false, Mode.NATIVE),
		new Vec(0xFFEEL, "vector_IRQ_native", "Native-mode IRQ vector", false, Mode.NATIVE),
		// Emulation vectors at $FFF4..$FFFF (RESET is handled above)
		new Vec(0xFFF4L, "vector_COP_emu", "Emulation-mode COP vector", false, Mode.EMULATION),
		new Vec(0xFFF8L, "vector_ABORT_emu", "Emulation-mode ABORT vector", false, Mode.EMULATION),
		new Vec(0xFFFAL, "vector_NMI_emu", "Emulation-mode NMI vector", false, Mode.EMULATION),
		new Vec(0xFFFEL, "vector_IRQ_BRK_emu", "Emulation-mode IRQ/BRK vector", false, Mode.EMULATION),
	};

	public static void apply(FlatProgramAPI fpa, AddressSpace bus, RomInfo romInfo,
			MessageLog log) {
		Memory mem = fpa.getCurrentProgram().getMemory();
		SymbolTable st = fpa.getCurrentProgram().getSymbolTable();
		ProgramContext ctx = fpa.getCurrentProgram().getProgramContext();
		Register efReg = ctx.getRegister("ctx_EF");
		Register mfReg = ctx.getRegister("ctx_MF");
		Register xfReg = ctx.getRegister("ctx_XF");

		PointerDataType ptr = new PointerDataType(new WordDataType(), 2);

		for (Vec v : VECTORS) {
			Address vecAddr = bus.getAddress(v.addr);
			try {
				// Apply pointer datatype on the vector slot itself.
				try {
					fpa.createData(vecAddr, ptr);
				}
				catch (Exception ignored) {
					// Already defined.
				}
				st.createLabel(vecAddr, v.name, SourceType.IMPORTED);
				fpa.setEOLComment(vecAddr, v.comment);

				// Resolve the target and create a function there.
				// `Memory.getShort` reads big-endian by default, so read bytes
				// explicitly and combine little-endian (SNES native order).
				int target;
				try {
					int lo = mem.getByte(vecAddr) & 0xFF;
					int hi = mem.getByte(vecAddr.add(1)) & 0xFF;
					target = (hi << 8) | lo;
				}
				catch (MemoryAccessException e) {
					continue;
				}
				if (target == 0x0000 || target == 0xFFFF) {
					continue;
				}
				Address tgt = bus.getAddress(target & 0xFFFFL);

				// Set per-vector context so e.g. native NMI handlers
				// disassemble in 16-bit M/X mode without needing a manual
				// override at every cartridge import.
				applyContextAt(ctx, efReg, mfReg, xfReg, tgt, v.mode, log);

				String funcName = "isr_" + v.name.replace("vector_", "").toLowerCase();
				if (v.name.equals("vector_RESET")) {
					funcName = "Reset";
				}
				SnesPostLoader.setFunction(fpa, tgt, funcName, v.entry, log);
			}
			catch (InvalidInputException e) {
				log.appendException(e);
			}
		}
	}

	private static void applyContextAt(ProgramContext ctx, Register efReg, Register mfReg,
			Register xfReg, Address at, Mode mode, MessageLog log) {
		if (at == null) return;
		BigInteger one = BigInteger.ONE;
		BigInteger zero = BigInteger.ZERO;
		try {
			if (mode == Mode.EMULATION) {
				if (efReg != null) ctx.setValue(efReg, at, at, one);
				if (mfReg != null) ctx.setValue(mfReg, at, at, one);
				if (xfReg != null) ctx.setValue(xfReg, at, at, one);
			}
			else {
				if (efReg != null) ctx.setValue(efReg, at, at, zero);
				if (mfReg != null) ctx.setValue(mfReg, at, at, zero);
				if (xfReg != null) ctx.setValue(xfReg, at, at, zero);
			}
		}
		catch (Exception e) {
			log.appendMsg("SnesVectors",
				"Could not set entry context for " + at + " (" + mode + "): " + e.getMessage());
		}
	}
}

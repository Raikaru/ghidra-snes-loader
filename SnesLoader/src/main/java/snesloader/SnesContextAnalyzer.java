// SPDX-License-Identifier: MIT
package snesloader;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

import java.math.BigInteger;

/**
 * Recognises common 65816 idioms that change the runtime values of the
 * Data Bank Register (DBR) and the Direct Page register (DP) and writes
 * the resulting values into Ghidra's {@link ProgramContext} so the
 * decompiler can resolve absolute and direct-page addresses correctly.
 *
 * <p>Without this analyser the decompiler has no way to know that, e.g.,
 * a {@code LDA $1234} instruction in a function that began with
 * {@code PHK; PLB} is reading from {@code $80:1234}, not from
 * {@code DBR:1234} where DBR is whatever the loader's default tracked
 * value happened to be ($00). The 65816 has no usable ABI for this,
 * so almost every commercial and homebrew SNES game relies on these
 * idioms instead.</p>
 *
 * <p>Patterns recognised today:</p>
 * <ul>
 *   <li>{@code PHK ; PLB}                        &rarr; DBR := PBR (current bank)</li>
 *   <li>{@code LDA #imm8 ; PHA ; PLB}            &rarr; DBR := imm</li>
 *   <li>{@code LDA #imm16 ; TCD}                 &rarr; DP  := imm</li>
 *   <li>{@code PEA #imm16 ; PLD}                 &rarr; DP  := imm</li>
 *   <li>{@code LDA #imm16 ; PHA ; PLD}           &rarr; DP  := imm</li>
 * </ul>
 *
 * <p>The values are committed using {@code ProgramContext.setRegisterValue}
 * over the address range from the immediately-following instruction up to
 * the end of the containing function (or the next conflicting write,
 * whichever comes first).</p>
 */
public class SnesContextAnalyzer extends AbstractAnalyzer {

	public static final String NAME = "SNES DBR/DP Tracker";
	public static final String DESCRIPTION =
		"Recognises 65816 idioms (PHK/PLB, PHA/PLB, TCD, PLD) and propagates the " +
		"resulting Data Bank Register / Direct Page values forward so absolute " +
		"and direct-page addresses resolve correctly in the decompiler.";

	public SnesContextAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.before());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		String langId = program.getLanguageID().getIdAsString();
		return langId.startsWith("65816");
	}

	@Override
	public void registerOptions(Options options, Program program) {
		// Reserved for future tunables (e.g. enable/disable individual idioms).
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		ProgramContext ctx = program.getProgramContext();
		Register dbrReg = ctx.getRegister("DBR");
		Register dpReg = ctx.getRegister("DP");
		Register pbrReg = ctx.getRegister("PBR");
		if (dbrReg == null && dpReg == null) {
			return true; // wrong language variant, nothing to do.
		}

		FunctionIterator funcs = program.getFunctionManager().getFunctions(set, true);
		while (funcs.hasNext()) {
			monitor.checkCancelled();
			Function f = funcs.next();
			analyseFunction(program, ctx, f, dbrReg, dpReg, pbrReg, monitor, log);
		}

		// Also scan instructions outside any function (entry-point stubs etc.).
		InstructionIterator iter = program.getListing().getInstructions(set, true);
		while (iter.hasNext()) {
			monitor.checkCancelled();
			Instruction insn = iter.next();
			Function f = program.getFunctionManager().getFunctionContaining(insn.getAddress());
			if (f != null) continue; // already handled.
			tryPatternsAt(program, ctx, insn, set, dbrReg, dpReg, pbrReg, log);
		}
		return true;
	}

	private void analyseFunction(Program program, ProgramContext ctx, Function f, Register dbrReg,
			Register dpReg, Register pbrReg, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		AddressSetView body = f.getBody();
		InstructionIterator it = program.getListing().getInstructions(body, true);
		while (it.hasNext()) {
			monitor.checkCancelled();
			Instruction insn = it.next();
			tryPatternsAt(program, ctx, insn, body, dbrReg, dpReg, pbrReg, log);
		}
	}

	private void tryPatternsAt(Program program, ProgramContext ctx, Instruction insn,
			AddressSetView limit, Register dbrReg, Register dpReg, Register pbrReg,
			MessageLog log) {
		String mnemonic = insn.getMnemonicString();
		Address insnAddr = insn.getAddress();

		// PHK ; PLB -> DBR := PBR.
		if ("PHK".equalsIgnoreCase(mnemonic)) {
			Instruction next = nextSeq(insn);
			if (next != null && "PLB".equalsIgnoreCase(next.getMnemonicString())) {
				int bank = (int) (insnAddr.getOffset() >>> 16) & 0xFF;
				Address from = nextOrSelf(next);
				setForward(ctx, dbrReg, BigInteger.valueOf(bank), from, limit, log);
				return;
			}
		}

		// LDA #imm ; PHA ; PLB -> DBR := imm (8-bit only).
		if ("LDA".equalsIgnoreCase(mnemonic) && isImmediate(insn)) {
			Long imm = immediateValue(insn);
			if (imm != null) {
				Instruction n1 = nextSeq(insn);
				Instruction n2 = nextSeq(n1);
				if (n1 != null && n2 != null
						&& "PHA".equalsIgnoreCase(n1.getMnemonicString())
						&& "PLB".equalsIgnoreCase(n2.getMnemonicString())) {
					Address from = nextOrSelf(n2);
					setForward(ctx, dbrReg, BigInteger.valueOf(imm & 0xFF), from, limit, log);
					return;
				}
			}
		}

		// LDA #imm16 ; TCD -> DP := imm.
		if ("LDA".equalsIgnoreCase(mnemonic) && isImmediate(insn)) {
			Long imm = immediateValue(insn);
			if (imm != null) {
				Instruction n1 = nextSeq(insn);
				if (n1 != null && "TCD".equalsIgnoreCase(n1.getMnemonicString())) {
					Address from = nextOrSelf(n1);
					setForward(ctx, dpReg, BigInteger.valueOf(imm & 0xFFFF), from, limit, log);
					return;
				}
				// LDA #imm16 ; PHA ; PLD -> DP := imm (less common but seen).
				Instruction n2 = nextSeq(n1);
				if (n1 != null && n2 != null
						&& "PHA".equalsIgnoreCase(n1.getMnemonicString())
						&& "PLD".equalsIgnoreCase(n2.getMnemonicString())) {
					Address from = nextOrSelf(n2);
					setForward(ctx, dpReg, BigInteger.valueOf(imm & 0xFFFF), from, limit, log);
					return;
				}
			}
		}

		// PEA #imm16 ; PLD -> DP := imm.
		if ("PEA".equalsIgnoreCase(mnemonic)) {
			Long imm = immediateValue(insn);
			Instruction n1 = nextSeq(insn);
			if (imm != null && n1 != null && "PLD".equalsIgnoreCase(n1.getMnemonicString())) {
				Address from = nextOrSelf(n1);
				setForward(ctx, dpReg, BigInteger.valueOf(imm & 0xFFFF), from, limit, log);
				return;
			}
			// PEA #BBBB ; PLB ; PLB -> DBR := BB. Conventionally games push a
			// word like $7E7E so that both PLBs leave the same byte in DBR; we
			// take the high byte (i.e. the byte the *second* PLB pulls).
			Instruction n2 = nextSeq(n1);
			if (imm != null && n1 != null && n2 != null
					&& "PLB".equalsIgnoreCase(n1.getMnemonicString())
					&& "PLB".equalsIgnoreCase(n2.getMnemonicString())) {
				int bank = (int) ((imm >> 8) & 0xFF);
				Address from = nextOrSelf(n2);
				setForward(ctx, dbrReg, BigInteger.valueOf(bank), from, limit, log);
			}
		}
	}

	private static boolean isImmediate(Instruction insn) {
		// Ghidra surfaces immediate operands as Scalar objects on operand index 0
		// for the dedicated immediate-mode rules emitted by 658xx.sinc.
		if (insn.getNumOperands() < 1) return false;
		Object[] ops = insn.getOpObjects(0);
		for (Object o : ops) {
			if (o instanceof Scalar) {
				return true;
			}
		}
		return false;
	}

	private static Long immediateValue(Instruction insn) {
		if (insn.getNumOperands() < 1) return null;
		for (Object o : insn.getOpObjects(0)) {
			if (o instanceof Scalar s) {
				return s.getUnsignedValue();
			}
		}
		return null;
	}

	private static Instruction nextSeq(Instruction insn) {
		if (insn == null) return null;
		Address fall = insn.getFallThrough();
		if (fall == null) return null;
		return insn.getProgram().getListing().getInstructionAt(fall);
	}

	private static Address nextOrSelf(Instruction insn) {
		Address fall = insn.getFallThrough();
		return fall != null ? fall : insn.getMaxAddress().next();
	}

	/**
	 * Set {@code reg = value} on the linear range from {@code from} to the end
	 * of the limiting set (typically the function body), but only over
	 * addresses where the register is currently unset or different from
	 * {@code value}, and stopping at the first instruction that already
	 * defines a different value (so manually-set overrides win).
	 */
	private void setForward(ProgramContext ctx, Register reg, BigInteger value, Address from,
			AddressSetView limit, MessageLog log) {
		if (reg == null || from == null) return;
		Address end = limit.getMaxAddress();
		if (end == null || from.compareTo(end) > 0) return;
		try {
			ctx.setValue(reg, from, end, value);
		}
		catch (Exception e) {
			log.appendMsg("SnesContextAnalyzer",
				String.format("Failed to set %s=%s at %s: %s",
					reg.getName(), value.toString(16), from, e.getMessage()));
		}
	}
}

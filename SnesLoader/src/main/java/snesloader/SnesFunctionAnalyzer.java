// SPDX-License-Identifier: MIT
package snesloader;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.SymbolTable;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

/**
 * Conservative function discovery for SNES 65816 programs.
 *
 * <p>Ghidra's generic analysis starts from the loader-created vector
 * functions, but commercial SNES games often keep many direct calls inside
 * banked code paths that need an extra pass to become decompiler-friendly.
 * This analyzer creates functions only at direct call-flow targets that Ghidra
 * has already decoded from instructions, and labels indirect call/jump sites
 * as candidates for later manual or game-specific jump-table work.</p>
 */
public class SnesFunctionAnalyzer extends AbstractAnalyzer {

	public static final String NAME = "SNES Function Discovery";
	public static final String DESCRIPTION =
		"Creates functions at direct 65816 JSR/JSL targets and labels indirect " +
		"jump/call sites as payload-free table candidates.";

	private static final int MAX_PASSES = 8;

	public SnesFunctionAnalyzer() {
		super(NAME, DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
		setPriority(AnalysisPriority.FUNCTION_ANALYSIS.after());
		setDefaultEnablement(true);
		setSupportsOneTimeAnalysis();
	}

	@Override
	public boolean canAnalyze(Program program) {
		return program.getLanguageID().getIdAsString().startsWith("65816");
	}

	@Override
	public void registerOptions(Options options, Program program) {
		// Reserved for future confidence/scan-depth tunables.
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		boolean changed;
		int pass = 0;
		do {
			changed = false;
			pass++;
			InstructionIterator it = program.getListing().getInstructions(set, true);
			while (it.hasNext()) {
				monitor.checkCancelled();
				Instruction insn = it.next();
				if (createDirectCallTargets(program, insn, monitor, log)) {
					changed = true;
				}
				labelIndirectCandidate(program, insn, log);
			}
		}
		while (changed && pass < MAX_PASSES);
		return true;
	}

	private boolean createDirectCallTargets(Program program, Instruction insn, TaskMonitor monitor,
			MessageLog log) {
		FlowType flowType = insn.getFlowType();
		String mnemonic = insn.getMnemonicString();
		boolean mnemonicCall = "JSR".equalsIgnoreCase(mnemonic) || "JSL".equalsIgnoreCase(mnemonic);
		if (!mnemonicCall && (flowType == null || !flowType.isCall())) {
			return false;
		}
		if (flowType != null && flowType.isComputed()) {
			return false;
		}

		boolean changed = false;
		for (Address target : directCallTargets(program, insn)) {
			if (target == null || !isExecutable(program, target)) {
				continue;
			}
			Function existing = program.getFunctionManager().getFunctionAt(target);
			if (existing != null) {
				continue;
			}
			try {
				if (program.getListing().getInstructionAt(target) == null) {
					new DisassembleCommand(target, null, true).applyTo(program, monitor);
				}
				if (program.getListing().getInstructionAt(target) == null) {
					continue;
				}
				String name = String.format("sub_%06X", target.getOffset() & 0xFFFFFFL);
				if (new CreateFunctionCmd(name, target, null, SourceType.ANALYSIS)
						.applyTo(program, monitor)) {
					changed = true;
				}
			}
			catch (Exception e) {
				log.appendMsg(NAME, "Could not create function at " + target + ": " + e.getMessage());
			}
		}
		return changed;
	}

	private Address[] directCallTargets(Program program, Instruction insn) {
		Address[] flows = insn.getFlows();
		if (flows.length > 0) {
			return flows;
		}

		String mnemonic = insn.getMnemonicString();
		if (!"JSR".equalsIgnoreCase(mnemonic) && !"JSL".equalsIgnoreCase(mnemonic)) {
			return new Address[0];
		}
		String text = insn.toString();
		if (text.contains("(") || text.contains("[") || text.contains(",")) {
			return new Address[0];
		}
		Long scalar = firstScalar(insn);
		if (scalar == null) {
			return new Address[0];
		}

		long target = scalar & ("JSL".equalsIgnoreCase(mnemonic) ? 0xFFFFFFL : 0xFFFFL);
		if ("JSR".equalsIgnoreCase(mnemonic)) {
			long bank = insn.getAddress().getOffset() & 0xFF0000L;
			target = bank | target;
		}
		return new Address[] {
			program.getAddressFactory().getDefaultAddressSpace().getAddress(target)
		};
	}

	private Long firstScalar(Instruction insn) {
		for (int i = 0; i < insn.getNumOperands(); i++) {
			for (Object obj : insn.getOpObjects(i)) {
				if (obj instanceof Scalar scalar) {
					return scalar.getUnsignedValue();
				}
			}
		}
		return null;
	}

	private void labelIndirectCandidate(Program program, Instruction insn, MessageLog log) {
		FlowType flowType = insn.getFlowType();
		if (flowType == null || (!flowType.isJump() && !flowType.isCall()) || !flowType.isComputed()) {
			return;
		}
		String mnemonic = insn.getMnemonicString();
		if (!"JMP".equalsIgnoreCase(mnemonic) && !"JSR".equalsIgnoreCase(mnemonic)
				&& !"JSL".equalsIgnoreCase(mnemonic)) {
			return;
		}
		Address at = insn.getAddress();
		SymbolTable st = program.getSymbolTable();
		String name = String.format("candidate_indirect_%06X", at.getOffset() & 0xFFFFFFL);
		try {
			if (!st.hasSymbol(at)) {
				st.createLabel(at, name, SourceType.ANALYSIS);
			}
			insn.setComment(Instruction.EOL_COMMENT,
				"SNES Function Discovery: indirect flow candidate; inspect as possible dispatch/jump table");
		}
		catch (InvalidInputException e) {
			log.appendException(e);
		}
	}

	private boolean isExecutable(Program program, Address target) {
		if (target == null || !program.getMemory().contains(target)) {
			return false;
		}
		var block = program.getMemory().getBlock(target);
		return block != null && block.isExecute();
	}
}

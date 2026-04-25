// SPDX-License-Identifier: MIT
//
// Headless post-script that dumps a structured summary of every artefact
// the SNES loader is expected to produce. CI greps the output for known
// markers ("MARK:" lines) and fails the build if any are missing.
//
// Design goals:
//   * No external dependencies beyond Ghidra's headless API.
//   * Output is line-oriented, prefixed, machine-greppable.
//   * Loud about what is *not* found: that's where regressions hide.
//
// Run with:
//   analyzeHeadless ... -postScript PrintSnesArtifacts.java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

public class PrintSnesArtifacts extends GhidraScript {

    @Override
    public void run() throws Exception {
        printHeader();
        printLanguage();
        printVectors();
        printMirrorBlocks();
        printMirrorLabels();
        printContextAtEntries();
    }

    private void printHeader() {
        println("MARK: PROGRAM " + currentProgram.getName());
    }

    private void printLanguage() {
        println("MARK: LANGUAGE " + currentProgram.getLanguageID().getIdAsString());
        println("MARK: COMPILER " + currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
    }

    private void printVectors() {
        SymbolTable st = currentProgram.getSymbolTable();
        String[] expected = {
            "vector_RESET",
            "vector_NMI_native",
            "vector_NMI_emu",
            "vector_IRQ_native",
            "vector_IRQ_BRK_emu",
            "vector_COP_native",
            "vector_COP_emu",
            "vector_BRK_native",
            "vector_ABORT_native",
            "vector_ABORT_emu",
        };
        for (String name : expected) {
            for (Symbol s : st.getSymbols(name)) {
                println(String.format("MARK: VECTOR %s @ %s", name, hex(s.getAddress())));
            }
        }
    }

    private void printMirrorBlocks() {
        for (MemoryBlock blk : currentProgram.getMemory().getBlocks()) {
            String n = blk.getName();
            if (n.startsWith("lowram_mirror") || n.startsWith("hwregs_mirror") || n.equals("hwregs") || n.equals("lowram_mirror")) {
                println(String.format("MARK: BLOCK %s %s-%s mapped=%s",
                    n, hex(blk.getStart()), hex(blk.getEnd()), blk.getType()));
            }
        }
    }

    private void printMirrorLabels() {
        SymbolTable st = currentProgram.getSymbolTable();
        // NMITIMEN is the canary: it must exist at $00:4200 and at the
        // mirrored copy in any populated bank, e.g. $01:4200.
        SymbolIterator it = st.getSymbols("NMITIMEN");
        int n = 0;
        while (it.hasNext()) {
            Symbol s = it.next();
            println(String.format("MARK: LABEL NMITIMEN @ %s", hex(s.getAddress())));
            n++;
        }
        println("MARK: LABEL_COUNT NMITIMEN " + n);
    }

    private void printContextAtEntries() throws Exception {
        // Spot-check that the loader landed a function at $00:8000 (the
        // RESET vector target on the synthesized ROM) and that its first
        // instruction is the SEI we encoded in the test stub.
        Function reset = getFunctionContaining(toAddr(0x008000L));
        if (reset != null) {
            Instruction insn = getInstructionAt(reset.getEntryPoint());
            println(String.format("MARK: ENTRY RESET %s -> %s", hex(reset.getEntryPoint()),
                insn != null ? insn.toString() : "(no instruction)"));
        }
    }

    /**
     * Format an Address as a fixed-width zero-padded hex offset, independent
     * of the address space prefix. Keeps the CI grep pattern stable across
     * Ghidra versions and address-space configurations.
     */
    private static String hex(Address a) {
        if (a == null) return "(null)";
        return String.format("%08x", a.getOffset() & 0xffffffffL);
    }
}

// SPDX-License-Identifier: MIT
//
// Headless post-script that dumps a structured summary of every artefact
// the SNES loader is expected to produce, including ProgramContext register
// values written by the DBR/DP analyser and per-vector mode overrides.
// CI greps the output for known markers ("MARK:" lines) and fails the build
// if any are missing.
//
// Marker grammar (deliberately line-oriented and machine-greppable):
//
//   MARK: PROGRAM <name>
//   MARK: LANGUAGE <id>
//   MARK: COMPILER <id>
//   MARK: MAPMODE <hex>
//   MARK: VECTOR <name> @ <hex>
//   MARK: BLOCK <name> <start>-<end> mapped=<type>
//   MARK: LABEL NMITIMEN @ <hex>
//   MARK: LABEL_COUNT NMITIMEN <n>
//   MARK: ENTRY <vector_name> <addr> -> <instruction>
//   MARK: CTX <reg> @ <hex> = <value>
//   MARK: CTX <reg> @ <hex> = (unset)
//
// Run with:
//   analyzeHeadless ... -postScript PrintSnesArtifacts.java

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.math.BigInteger;

public class PrintSnesArtifacts extends GhidraScript {

    @Override
    public void run() throws Exception {
        printHeader();
        printLanguage();
        printMapMode();
        printVectors();
        printMirrorBlocks();
        printMirrorLabels();
        printContextAtEntries();
        printContextAtIdiomTestPoints();
    }

    private void printHeader() {
        println("MARK: PROGRAM " + currentProgram.getName());
    }

    private void printLanguage() {
        println("MARK: LANGUAGE " + currentProgram.getLanguageID().getIdAsString());
        println("MARK: COMPILER "
                + currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString());
    }

    /**
     * Read the cartridge map mode out of the header.
     *
     * <p>For both LoROM and HiROM the byte ends up visible at {@code $00:FFD5}
     * after import: LoROM maps file offset {@code $7FD5} there as part of the
     * bank-0 ROM block, HiROM mirrors {@code $C0:FFD5} (file offset
     * {@code $FFD5}) into bank 0. The asserter pins the expected value per
     * ROM kind so a mis-detection (LoROM marshalled as HiROM or vice-versa)
     * fails loudly.</p>
     */
    private void printMapMode() {
        long[] candidates = { 0x00FFD5L, 0x007FD5L };
        for (long off : candidates) {
            try {
                Address a = toAddr(off);
                if (a == null) continue;
                int b = currentProgram.getMemory().getByte(a) & 0xFF;
                println(String.format("MARK: MAPMODE @ %s = %02x", hex(a), b));
            }
            catch (Exception ignored) {
                // not mapped in the current cart kind
            }
        }
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
            if (n.startsWith("lowram_mirror") || n.startsWith("hwregs_mirror")
                    || n.startsWith("rom_") || n.equals("hwregs")
                    || n.equals("lowram_mirror") || n.equals("wram_low") || n.equals("wram")) {
                println(String.format("MARK: BLOCK %s %s-%s mapped=%s",
                    n, hex(blk.getStart()), hex(blk.getEnd()), blk.getType()));
            }
        }
    }

    private void printMirrorLabels() {
        SymbolTable st = currentProgram.getSymbolTable();
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
        Function reset = getFunctionContaining(toAddr(0x008000L));
        if (reset != null) {
            Instruction insn = getInstructionAt(reset.getEntryPoint());
            println(String.format("MARK: ENTRY RESET %s -> %s",
                hex(reset.getEntryPoint()),
                insn != null ? insn.toString() : "(no instruction)"));
        }
        // Per-vector E/M/X overrides: emulation-mode vectors should be E=M=X=1
        // at their entry addresses. The RESET stub at $00:8000 is the easiest
        // canary. Emit them whether or not the analyser changed anything;
        // the asserter decides which values are "required".
        Address entry = (reset != null) ? reset.getEntryPoint() : toAddr(0x008000L);
        dumpContext("ctx_EF", entry);
        dumpContext("ctx_MF", entry);
        dumpContext("ctx_XF", entry);
    }

    /**
     * Spot-check ProgramContext at the addresses where the idiom synth ROM
     * places its DBR / DP test points. The min-LoROM stub doesn't go through
     * those instructions, so on that ROM these markers will report "(unset)".
     * That's deliberate -- the idiom workflow's asserter is the only one
     * that pins concrete values.
     */
    private void printContextAtIdiomTestPoints() {
        // See tests/synth-idiom-lorom.py for the exact byte layout.
        // $00:8009  is "LDA $1234" -- expected DBR == 0x80.
        // $00:8012  is "LDA $5678" -- expected DP  == 0x1234.
        dumpContext("DBR", toAddr(0x008009L));
        dumpContext("DP",  toAddr(0x008012L));
    }

    private void dumpContext(String regName, Address at) {
        if (at == null) {
            println(String.format("MARK: CTX %s @ (null) = (unset)", regName));
            return;
        }
        ProgramContext ctx = currentProgram.getProgramContext();
        Register reg = ctx.getRegister(regName);
        if (reg == null) {
            println(String.format("MARK: CTX %s @ %s = (no-such-register)",
                regName, hex(at)));
            return;
        }
        BigInteger v = ctx.getValue(reg, at, false);
        if (v == null) {
            println(String.format("MARK: CTX %s @ %s = (unset)", regName, hex(at)));
        }
        else {
            println(String.format("MARK: CTX %s @ %s = %s",
                regName, hex(at), v.toString(16)));
        }
    }

    private static String hex(Address a) {
        if (a == null) return "(null)";
        return String.format("%08x", a.getOffset() & 0xffffffffL);
    }
}

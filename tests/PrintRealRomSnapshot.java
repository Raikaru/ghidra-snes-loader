// SPDX-License-Identifier: MIT
//
// Headless post-script for real-ROM smoke tests. Dumps a richer
// structural snapshot than ``PrintSnesArtifacts.java``: in addition
// to the structural MARK: lines, it counts how many of the things
// the loader is supposed to do actually landed on this cartridge,
// so we can compare across the corpus without diffing huge logs.
//
// Markers it adds on top of the synthetic-ROM post-script:
//
//   MARK: TITLE "<header title>"
//   MARK: ROMKIND <text>           e.g. "LoROM", "HiROM", "ExHiROM"
//   MARK: COPROC <text>            e.g. "SA1", "GSU", "DSP1", "CX4", "NONE"
//   MARK: COUNT FUNCTIONS <n>
//   MARK: COUNT BLOCKS <n>
//   MARK: COUNT SYMBOLS_TOTAL <n>
//   MARK: COUNT SYMBOLS_HW <n>     (symbols inside hwregs/hwregs_mirror_*)
//   MARK: COUNT DBR_OVERRIDES <n>  (instruction addresses with DBR != default)
//   MARK: COUNT DP_OVERRIDES  <n>  (instruction addresses with DP  != 0)
//   MARK: SAMPLE RESET <addr> -> <insn>  (first 4 instructions after RESET)
//
// Together those let an offline reviewer answer in one glance: did the
// loader detect the right cart type, does the DBR/DP analyser actually
// fire on real code, and how rich is the symbolisation density.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ProgramContext;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolIterator;
import ghidra.program.model.symbol.SymbolTable;

import java.math.BigInteger;
import java.util.HashSet;
import java.util.Set;

public class PrintRealRomSnapshot extends GhidraScript {

    @Override
    public void run() throws Exception {
        println("MARK: PROGRAM " + currentProgram.getName());
        println("MARK: LANGUAGE "
                + currentProgram.getLanguageID().getIdAsString());

        printHeaderInfo();
        printCounts();
        printAnalyserCoverage();
        printResetSample();
    }

    /**
     * Pull the cartridge title and map-mode byte from where the loader
     * placed them. Also classify ROMKIND from the map mode and try to
     * recognise the most common coprocessor families from the cartridge
     * type byte at $00:FFD6.
     */
    private void printHeaderInfo() {
        String titleStr = "";
        try {
            Address title = toAddr(0x00FFC0L);
            byte[] tb = new byte[21];
            currentProgram.getMemory().getBytes(title, tb);
            StringBuilder sb = new StringBuilder();
            for (byte b : tb) {
                int c = b & 0xFF;
                sb.append(c >= 0x20 && c < 0x7F ? (char) c : '.');
            }
            titleStr = sb.toString().trim();
            println("MARK: TITLE \"" + titleStr + "\"");
        }
        catch (Exception e) {
            println("MARK: TITLE (unreadable: " + e.getMessage() + ")");
        }

        int map = readByteOrMinus(0x00FFD5L);
        int cartType = readByteOrMinus(0x00FFD6L);
        println(String.format("MARK: MAPMODE = %02x", map & 0xFF));
        println(String.format("MARK: CARTTYPE = %02x", cartType & 0xFF));
        println("MARK: ROMKIND " + classifyRomKind(map));
        println("MARK: COPROC " + classifyCoprocessor(map, cartType, titleStr));
    }

    private int readByteOrMinus(long off) {
        try {
            return currentProgram.getMemory().getByte(toAddr(off)) & 0xFF;
        }
        catch (Exception e) {
            return -1;
        }
    }

    private static String classifyRomKind(int map) {
        if (map < 0) return "(unreadable)";
        int lo = map & 0x0F;
        switch (lo) {
            case 0x0:                  return "LoROM";
            case 0x1:                  return "HiROM";
            case 0x2:                  return "LoROM/SDD-1";
            case 0x3:                  return "LoROM/SA-1";
            case 0x5:                  return "ExHiROM";
            case 0xA:                  return "HiROM/SPC7110";
            default: return String.format("(unknown map=%02x)", map);
        }
    }

    /**
     * Mirror SnesHeader's coprocessor classification logic at the marker
     * level so the smoke runner can grep for "COPROC GSU" without parsing
     * SnesHeader-formatted strings out of the loader log.
     *
     * <p>The cartridge-type byte at $00:FFD6 has the form ``hi:lo``. The
     * low nibble selects one of:
     * <ul>
     * <li>0..2: plain ROM, ROM+RAM, ROM+RAM+battery -- <b>no coprocessor</b></li>
     * <li>3..6: ROM+coprocessor (with optional RAM/battery), and the
     *     high nibble identifies which coprocessor family.</li>
     * </ul>
     * For ``hi == 0xF`` ("Custom") we use the full byte rather than just
     * the nibble: $F3 = CX4, $F5/$F9 = SPC7110, $F6 = ST010/011, $F8 =
     * ST018. This mirrors the SnesHeader.getCoprocessor() switch in the
     * loader so the smoke marker doesn't disagree with the loader's own
     * classification.</p>
     */
    private static String classifyCoprocessor(int map, int cartType, String title) {
        if (cartType < 0) return "(unreadable)";
        int lo = cartType & 0x0F;
        int hi = (cartType >> 4) & 0x0F;
        // Low-nibble 0..2 are plain ROM/ROM+RAM/ROM+RAM+battery -- no chip.
        // Exception: some early DSP games (e.g. Super Bowling) set cart type
        // 0x00 even though a DSP chip is present. Override by ROM title.
        if (lo < 3 && hi == 0 && !"SUPER BOWLING".equals(title)) return "NONE";
        switch (hi) {
            case 0x0: return "DSPx";
            case 0x1: return "GSU";
            case 0x2: return "OBC1";
            case 0x3: return "SA1";
            case 0x4: return "SDD1";
            case 0x5: return "SRTC";
            case 0xE: return "OTHER";
            case 0xF:
                switch (cartType & 0xFF) {
                    case 0xF3: return "CX4";
                    case 0xF5: return "SPC7110";
                    case 0xF9: return "SPC7110";
                    case 0xF6: return "ST010_011";
                    case 0xF8: return "ST018";
                    default:   return String.format("CUSTOM_%02x", cartType);
                }
            default: return String.format("UNKNOWN_HI_%x", hi);
        }
    }

    private void printCounts() {
        int funcs = 0;
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        while (fit.hasNext()) { fit.next(); funcs++; }
        println("MARK: COUNT FUNCTIONS " + funcs);

        int blocks = 0;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) blocks++;
        println("MARK: COUNT BLOCKS " + blocks);

        SymbolTable st = currentProgram.getSymbolTable();
        int total = 0;
        SymbolIterator allSyms = st.getAllSymbols(true);
        while (allSyms.hasNext()) { allSyms.next(); total++; }
        println("MARK: COUNT SYMBOLS_TOTAL " + total);

        // Hardware-register symbols: anything in the primary "hwregs"
        // block. Mirror blocks (hwregs_mirror_XX) deliberately span a
        // whole 64 KiB bank with byte-mapping for emulation accuracy,
        // so their address range overlaps every other block in that
        // bank -- counting symbols by mirror would count almost every
        // labelled instruction in the whole program. The primary block
        // is the only one with the actual register labels on it.
        int hwSyms = 0;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            if (!b.getName().equals("hwregs")) continue;
            SymbolIterator it = st.getSymbolIterator(b.getStart(), true);
            while (it.hasNext()) {
                Symbol s = it.next();
                Address a = s.getAddress();
                if (a.compareTo(b.getEnd()) > 0) break;
                hwSyms++;
            }
        }
        println("MARK: COUNT SYMBOLS_HW " + hwSyms);
    }

    /**
     * Count how many distinct instruction addresses have a DBR/DP value
     * the SnesContextAnalyzer must have written -- i.e. DBR != $00 (the
     * loader's default) and DP != $0000.
     *
     * <p>We dedupe on instruction address. If the analyser propagates
     * DBR=$80 across 1000 instructions in one function, that's still
     * 1000 in this count -- which is what we want, because it directly
     * answers "how much of this cart's code now decompiles with bank
     * resolution".</p>
     */
    private void printAnalyserCoverage() throws Exception {
        ProgramContext ctx = currentProgram.getProgramContext();
        Register dbr = ctx.getRegister("DBR");
        Register dp  = ctx.getRegister("DP");
        if (dbr == null || dp == null) {
            println("MARK: COUNT DBR_OVERRIDES (no-DBR-register)");
            return;
        }
        Set<Address> dbrHits = new HashSet<>();
        Set<Address> dpHits  = new HashSet<>();
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        while (fit.hasNext()) {
            Function f = fit.next();
            AddressSetView body = f.getBody();
            var iter = currentProgram.getListing().getInstructions(body, true);
            while (iter.hasNext()) {
                Instruction insn = iter.next();
                BigInteger d = ctx.getValue(dbr, insn.getAddress(), false);
                BigInteger p = ctx.getValue(dp,  insn.getAddress(), false);
                if (d != null && d.signum() != 0) dbrHits.add(insn.getAddress());
                if (p != null && p.signum() != 0) dpHits.add(insn.getAddress());
            }
        }
        println("MARK: COUNT DBR_OVERRIDES " + dbrHits.size());
        println("MARK: COUNT DP_OVERRIDES " + dpHits.size());
    }

    private void printResetSample() throws Exception {
        Address resetEntry = null;
        SymbolIterator it = currentProgram.getSymbolTable().getSymbols("Reset");
        if (it.hasNext()) resetEntry = it.next().getAddress();
        if (resetEntry == null) {
            // fall back to the canonical post-reset entry point
            resetEntry = toAddr(0x008000L);
        }
        println("MARK: ENTRY RESET " + fmt(resetEntry));
        Address cur = resetEntry;
        for (int i = 0; i < 4; i++) {
            Instruction insn = getInstructionAt(cur);
            if (insn == null) {
                println(String.format("MARK: SAMPLE RESET %s -> (no insn)",
                    fmt(cur)));
                break;
            }
            println(String.format("MARK: SAMPLE RESET %s -> %s",
                fmt(insn.getAddress()), insn.toString()));
            Address fall = insn.getFallThrough();
            if (fall == null) break;
            cur = fall;
        }
    }

    private static String fmt(Address a) {
        if (a == null) return "(null)";
        return String.format("%08x", a.getOffset() & 0xffffffffL);
    }
}

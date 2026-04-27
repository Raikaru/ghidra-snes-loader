// SPDX-License-Identifier: MIT
//
// Payload-free flow/table candidate exporter for local SNES decomp triage.
// It emits addresses, counts, and candidate kinds only. It must not emit ROM
// bytes, copied disassembly, decoded text, scripts, maps, graphics, audio, or
// raw table contents.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;

import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class ExportSnesFlowCandidates extends GhidraScript {

    private static final int MAX_CANDIDATES = 256;

    @Override
    public void run() throws Exception {
        List<Candidate> indirect = collectIndirectFlow();
        List<Candidate> wordTables = collectPointerTablesNearIndirect(indirect, false);
        List<Candidate> longTables = collectPointerTablesNearIndirect(indirect, true);

        StringBuilder out = new StringBuilder();
        out.append("{");
        field(out, "program", currentProgram.getName()).append(",");
        out.append("\"counts\":{");
        out.append("\"indirect_flow_sites\":").append(indirect.size()).append(",");
        out.append("\"word_pointer_table_candidates\":").append(wordTables.size()).append(",");
        out.append("\"long_pointer_table_candidates\":").append(longTables.size()).append(",");
        out.append("\"candidate_cap\":").append(MAX_CANDIDATES).append(",");
        out.append("\"word_pointer_candidates_capped\":").append(wordTables.size() >= MAX_CANDIDATES).append(",");
        out.append("\"long_pointer_candidates_capped\":").append(longTables.size() >= MAX_CANDIDATES);
        out.append("},");
        appendCandidates(out, "indirect_flow_sites", indirect).append(",");
        appendCandidates(out, "word_pointer_tables", wordTables).append(",");
        appendCandidates(out, "long_pointer_tables", longTables);
        out.append("}");
        println("JSON: " + out.toString());
    }

    private List<Candidate> collectIndirectFlow() {
        List<Candidate> out = new ArrayList<>();
        var iter = currentProgram.getListing().getInstructions(true);
        while (iter.hasNext() && out.size() < MAX_CANDIDATES) {
            Instruction insn = iter.next();
            if (!insn.getFlowType().isComputed()) continue;
            if (!insn.getFlowType().isJump() && !insn.getFlowType().isCall()) continue;
            String mnemonic = insn.getMnemonicString().toUpperCase();
            if (!mnemonic.equals("JMP") && !mnemonic.equals("JSR") && !mnemonic.equals("JSL")) continue;
            out.add(new Candidate(hex(insn.getAddress()), mnemonic, 1));
        }
        return out;
    }

    private List<Candidate> collectPointerTablesNearIndirect(List<Candidate> indirect, boolean longPointers) throws Exception {
        List<Candidate> out = new ArrayList<>();
        Set<String> seen = new HashSet<>();
        for (Candidate site : indirect) {
            if (out.size() >= MAX_CANDIDATES) break;
            long center = Long.parseUnsignedLong(site.address, 16);
            long lo = Math.max(0, center - 0x200);
            long hi = center + 0x200;
            long stride = longPointers ? 3L : 2L;
            for (long pos = lo; pos <= hi && out.size() < MAX_CANDIDATES; pos++) {
                Address at = toAddr(pos);
                if (!isInitializedRom(at)) continue;
                int entries = countPointerRun(pos, longPointers);
                if (entries >= (longPointers ? 3 : 4) && hasFunctionTarget(pos, entries, longPointers)) {
                    String kind = longPointers ? "near_indirect_long_pointer_table" : "near_indirect_word_pointer_table";
                    String key = kind + ":" + hex(at);
                    if (seen.add(key)) {
                        out.add(new Candidate(hex(at), kind, entries));
                    }
                    pos += stride * entries;
                }
            }
        }
        return out;
    }

    private int countPointerRun(long pos, boolean longPointers) {
        int count = 0;
        long cursor = pos;
        while (count < 64) {
            try {
                if (!isInitializedRom(toAddr(cursor))) break;
                int lo = currentProgram.getMemory().getByte(toAddr(cursor)) & 0xff;
                int hi = currentProgram.getMemory().getByte(toAddr(cursor + 1)) & 0xff;
                int word = (hi << 8) | lo;
                if (word < 0x8000 || word == 0xffff) break;
                if (longPointers) {
                    int bank = currentProgram.getMemory().getByte(toAddr(cursor + 2)) & 0xff;
                    long target = (((long) bank) << 16) | word;
                    if (!isInitializedRom(toAddr(target))) break;
                }
                else {
                    long target = (pos & 0xff0000L) | word;
                    if (!isInitializedRom(toAddr(target))) break;
                }
                count++;
                cursor += longPointers ? 3L : 2L;
            }
            catch (Exception e) {
                break;
            }
        }
        return count;
    }

    private boolean hasFunctionTarget(long pos, int entries, boolean longPointers) {
        long stride = longPointers ? 3L : 2L;
        int checked = Math.min(entries, 8);
        boolean sawFunction = false;
        for (int i = 0; i < checked; i++) {
            try {
                long cursor = pos + stride * i;
                int lo = currentProgram.getMemory().getByte(toAddr(cursor)) & 0xff;
                int hi = currentProgram.getMemory().getByte(toAddr(cursor + 1)) & 0xff;
                long target = (hi << 8) | lo;
                if (longPointers) {
                    int bank = currentProgram.getMemory().getByte(toAddr(cursor + 2)) & 0xff;
                    target |= ((long) bank) << 16;
                }
                else {
                    target |= pos & 0xff0000L;
                }
                if (!isInitializedRom(toAddr(target))) return false;
                if (currentProgram.getFunctionManager().getFunctionAt(toAddr(target)) != null) {
                    sawFunction = true;
                }
            }
            catch (Exception ignored) {
                return false;
            }
        }
        return sawFunction;
    }

    private boolean isInitializedRom(Address address) {
        if (address == null || !currentProgram.getMemory().contains(address)) return false;
        MemoryBlock block = currentProgram.getMemory().getBlock(address);
        return block != null && block.isInitialized() && block.getName().startsWith("rom_");
    }

    private StringBuilder appendCandidates(StringBuilder out, String name, List<Candidate> candidates) {
        out.append("\"").append(name).append("\":[");
        boolean first = true;
        for (Candidate candidate : candidates) {
            if (!first) out.append(",");
            out.append("{");
            field(out, "address", candidate.address).append(",");
            field(out, "kind", candidate.kind).append(",");
            out.append("\"entries\":").append(candidate.entries);
            out.append("}");
            first = false;
        }
        out.append("]");
        return out;
    }

    private static class Candidate {
        final String address;
        final String kind;
        final int entries;

        Candidate(String address, String kind, int entries) {
            this.address = address;
            this.kind = kind;
            this.entries = entries;
        }
    }

    private static StringBuilder field(StringBuilder out, String name, String value) {
        out.append("\"").append(escape(name)).append("\":\"").append(escape(value)).append("\"");
        return out;
    }

    private static String hex(Address address) {
        if (address == null) return "";
        return String.format("%08x", address.getOffset() & 0xffffffffL);
    }

    private static String escape(String value) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < value.length(); i++) {
            char c = value.charAt(i);
            switch (c) {
                case '\\': out.append("\\\\"); break;
                case '"': out.append("\\\""); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (c < 0x20) out.append(String.format("\\u%04x", (int) c));
                    else out.append(c);
            }
        }
        return out.toString();
    }
}

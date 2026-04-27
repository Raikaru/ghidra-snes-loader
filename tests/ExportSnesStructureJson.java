// SPDX-License-Identifier: MIT
//
// Headless post-script that emits a payload-free JSON summary of a loaded SNES
// program. It records structure only: language, blocks, vector symbols, counts,
// and analyser coverage. It must not emit ROM bytes, decoded text, screenshots,
// asset dumps, scripts, maps, audio samples, or save data.

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

public class ExportSnesStructureJson extends GhidraScript {

    @Override
    public void run() throws Exception {
        StringBuilder out = new StringBuilder();
        out.append("{");
        field(out, "program", currentProgram.getName()).append(",");
        field(out, "language", currentProgram.getLanguageID().getIdAsString()).append(",");
        field(out, "compiler", currentProgram.getCompilerSpec().getCompilerSpecID().getIdAsString()).append(",");
        field(out, "map_mode", readByteHex(0x00ffd5L)).append(",");
        appendVectors(out).append(",");
        appendBlocks(out).append(",");
        appendCounts(out);
        out.append("}");
        println("JSON: " + out.toString());
    }

    private StringBuilder appendVectors(StringBuilder out) {
        out.append("\"vectors\":[");
        SymbolTable st = currentProgram.getSymbolTable();
        String[][] vectors = {
            { "vector_RESET", "Reset" },
            { "vector_NMI_native", "isr_nmi_native" },
            { "vector_NMI_emu", "isr_nmi_emu" },
            { "vector_IRQ_native", "isr_irq_native" },
            { "vector_IRQ_BRK_emu", "isr_irq_brk_emu" },
            { "vector_COP_native", "isr_cop_native" },
            { "vector_COP_emu", "isr_cop_emu" },
            { "vector_BRK_native", "isr_brk_native" },
            { "vector_ABORT_native", "isr_abort_native" },
            { "vector_ABORT_emu", "isr_abort_emu" },
        };
        boolean first = true;
        for (String[] vector : vectors) {
            String name = vector[0];
            String functionName = vector[1];
            for (Symbol s : st.getSymbols(name)) {
                if (!first) out.append(",");
                Address target = readVectorTarget(s.getAddress());
                Function function = target == null
                    ? null
                    : currentProgram.getFunctionManager().getFunctionAt(target);
                out.append("{");
                field(out, "name", name).append(",");
                field(out, "address", hex(s.getAddress())).append(",");
                field(out, "target", hex(target)).append(",");
                field(out, "expected_function", functionName).append(",");
                field(out, "function", function == null ? "" : function.getName());
                out.append("}");
                first = false;
            }
        }
        out.append("]");
        return out;
    }

    private StringBuilder appendBlocks(StringBuilder out) {
        out.append("\"memory_blocks\":[");
        boolean first = true;
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!first) out.append(",");
            out.append("{");
            field(out, "name", block.getName()).append(",");
            field(out, "start", hex(block.getStart())).append(",");
            field(out, "end", hex(block.getEnd())).append(",");
            field(out, "type", block.getType().toString()).append(",");
            out.append("\"size\":").append(block.getSize());
            out.append("}");
            first = false;
        }
        out.append("]");
        return out;
    }

    private StringBuilder appendCounts(StringBuilder out) throws Exception {
        int functions = 0;
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        while (fit.hasNext()) {
            fit.next();
            functions++;
        }

        int blocks = 0;
        for (MemoryBlock ignored : currentProgram.getMemory().getBlocks()) {
            blocks++;
        }

        int symbols = 0;
        SymbolIterator allSyms = currentProgram.getSymbolTable().getAllSymbols(true);
        while (allSyms.hasNext()) {
            allSyms.next();
            symbols++;
        }

        int hwSymbols = countPrimaryHwSymbols();
        int[] contextCoverage = countContextCoverage();

        out.append("\"counts\":{");
        out.append("\"functions\":").append(functions).append(",");
        out.append("\"memory_blocks\":").append(blocks).append(",");
        out.append("\"symbols_total\":").append(symbols).append(",");
        out.append("\"symbols_hw_primary\":").append(hwSymbols).append(",");
        out.append("\"dbr_override_instructions\":").append(contextCoverage[0]).append(",");
        out.append("\"dp_override_instructions\":").append(contextCoverage[1]);
        out.append("}");
        return out;
    }

    private int countPrimaryHwSymbols() {
        int count = 0;
        SymbolTable st = currentProgram.getSymbolTable();
        for (MemoryBlock block : currentProgram.getMemory().getBlocks()) {
            if (!block.getName().equals("hwregs")) continue;
            SymbolIterator it = st.getSymbolIterator(block.getStart(), true);
            while (it.hasNext()) {
                Symbol symbol = it.next();
                Address address = symbol.getAddress();
                if (address.compareTo(block.getEnd()) > 0) break;
                count++;
            }
        }
        return count;
    }

    private int[] countContextCoverage() throws Exception {
        ProgramContext ctx = currentProgram.getProgramContext();
        Register dbr = ctx.getRegister("DBR");
        Register dp = ctx.getRegister("DP");
        if (dbr == null || dp == null) {
            return new int[] { 0, 0 };
        }

        Set<Address> dbrHits = new HashSet<>();
        Set<Address> dpHits = new HashSet<>();
        FunctionIterator fit = currentProgram.getFunctionManager().getFunctions(true);
        while (fit.hasNext()) {
            Function function = fit.next();
            AddressSetView body = function.getBody();
            var iter = currentProgram.getListing().getInstructions(body, true);
            while (iter.hasNext()) {
                Instruction instruction = iter.next();
                BigInteger dbrValue = ctx.getValue(dbr, instruction.getAddress(), false);
                BigInteger dpValue = ctx.getValue(dp, instruction.getAddress(), false);
                if (dbrValue != null && dbrValue.signum() != 0) dbrHits.add(instruction.getAddress());
                if (dpValue != null && dpValue.signum() != 0) dpHits.add(instruction.getAddress());
            }
        }
        return new int[] { dbrHits.size(), dpHits.size() };
    }

    private String readByteHex(long offset) {
        try {
            return String.format("%02x", currentProgram.getMemory().getByte(toAddr(offset)) & 0xff);
        }
        catch (Exception e) {
            return "";
        }
    }

    private Address readVectorTarget(Address vectorAddress) {
        try {
            int lo = currentProgram.getMemory().getByte(vectorAddress) & 0xff;
            int hi = currentProgram.getMemory().getByte(vectorAddress.add(1)) & 0xff;
            int target = (hi << 8) | lo;
            if (target == 0x0000 || target == 0xffff) {
                return null;
            }
            return toAddr(target & 0xffffL);
        }
        catch (Exception e) {
            return null;
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
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int) c));
                    }
                    else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }
}

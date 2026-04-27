// SPDX-License-Identifier: MIT
//
// Headless post-script that emits payload-free APU/SPC interaction candidates.
// It reports instruction addresses that reference the SNES APU I/O ports
// $2140-$2143 or contain scalar APU-port candidates, plus nearby function
// names when available. It must not emit ROM
// bytes, copied disassembly, decoded text, audio, samples, or assets.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Reference;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.TreeSet;

public class ExportSnesApuCandidates extends GhidraScript {

    @Override
    public void run() throws Exception {
        Map<String, TreeSet<String>> byFunction = new LinkedHashMap<>();
        int refInstructions = 0;
        int scalarCandidateInstructions = 0;

        var iter = currentProgram.getListing().getInstructions(true);
        while (iter.hasNext()) {
            Instruction instruction = iter.next();
            TreeSet<String> ports = new TreeSet<>();
            boolean hadReference = false;
            boolean hadScalarCandidate = false;
            for (Reference ref : instruction.getReferencesFrom()) {
                Address to = ref.getToAddress();
                if (to == null) continue;
                int low = (int) (to.getOffset() & 0xffffL);
                if (low >= 0x2140 && low <= 0x2143) {
                    ports.add(String.format("%04x", low));
                    hadReference = true;
                }
            }
            for (int i = 0; i < instruction.getNumOperands(); i++) {
                for (Object obj : instruction.getOpObjects(i)) {
                    if (obj instanceof Scalar scalar) {
                        long raw = scalar.getUnsignedValue();
                        if (raw > 0xffffL) continue;
                        long value = raw & 0xffffL;
                        if (value >= 0x2140 && value <= 0x2143) {
                            ports.add(String.format("%04x", value));
                            hadScalarCandidate = true;
                        }
                    }
                }
            }
            if (ports.isEmpty()) continue;

            if (hadReference) refInstructions++;
            if (hadScalarCandidate && !hadReference) scalarCandidateInstructions++;
            Function function = getFunctionContaining(instruction.getAddress());
            String key = function == null
                ? "(no_function)@" + hex(instruction.getAddress())
                : function.getName() + "@" + hex(function.getEntryPoint());
            byFunction.computeIfAbsent(key, ignored -> new TreeSet<>()).addAll(ports);
        }

        StringBuilder out = new StringBuilder();
        out.append("{");
        field(out, "program", currentProgram.getName()).append(",");
        out.append("\"apu_port_reference_instructions\":").append(refInstructions).append(",");
        out.append("\"apu_port_scalar_candidate_instructions\":").append(scalarCandidateInstructions).append(",");
        out.append("\"candidate_functions\":[");
        boolean first = true;
        for (Map.Entry<String, TreeSet<String>> entry : byFunction.entrySet()) {
            if (!first) out.append(",");
            out.append("{");
            field(out, "function", entry.getKey()).append(",");
            out.append("\"ports\":[");
            boolean firstPort = true;
            for (String port : entry.getValue()) {
                if (!firstPort) out.append(",");
                out.append("\"").append(port).append("\"");
                firstPort = false;
            }
            out.append("]}");
            first = false;
        }
        out.append("],");
        out.append("\"candidate_instructions\":[");
        boolean firstInstruction = true;
        iter = currentProgram.getListing().getInstructions(true);
        while (iter.hasNext()) {
            Instruction instruction = iter.next();
            TreeSet<String> ports = portsFor(instruction);
            if (ports.isEmpty()) continue;
            if (!firstInstruction) out.append(",");
            out.append("{");
            field(out, "address", hex(instruction.getAddress())).append(",");
            Function function = getFunctionContaining(instruction.getAddress());
            field(out, "function", function == null ? "" : function.getName()).append(",");
            out.append("\"ports\":[");
            boolean firstPort = true;
            for (String port : ports) {
                if (!firstPort) out.append(",");
                out.append("\"").append(port).append("\"");
                firstPort = false;
            }
            out.append("]}");
            firstInstruction = false;
        }
        out.append("]}");
        println("JSON: " + out.toString());
    }

    private TreeSet<String> portsFor(Instruction instruction) {
        TreeSet<String> ports = new TreeSet<>();
        for (Reference ref : instruction.getReferencesFrom()) {
            Address to = ref.getToAddress();
            if (to == null) continue;
            int low = (int) (to.getOffset() & 0xffffL);
            if (low >= 0x2140 && low <= 0x2143) {
                ports.add(String.format("%04x", low));
            }
        }
        for (int i = 0; i < instruction.getNumOperands(); i++) {
            for (Object obj : instruction.getOpObjects(i)) {
                if (obj instanceof Scalar scalar) {
                    long raw = scalar.getUnsignedValue();
                    if (raw > 0xffffL) continue;
                    if (raw >= 0x2140 && raw <= 0x2143) {
                        ports.add(String.format("%04x", raw));
                    }
                }
            }
        }
        return ports;
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

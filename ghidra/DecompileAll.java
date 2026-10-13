// DecompileAll.java — Ghidra headless post-script (Java; Ghidra 11/12 compatible).
//
// 1. locates the executable memory block (NEVER use getImageBase(): a raw
//    BinaryLoader import reports image base 0 while the block actually sits at
//    the requested -loader-baseAddr, so getBlock(getImageBase()) returns null);
// 2. forces Thumb mode (TMode=1) over the whole block BEFORE any disassembly —
//    it only takes effect on a fresh import or after clearListing;
// 3. scans PUSH prologues, disassembles and creates the missing functions;
// 4. decompiles every function in [lo, hi] to <outdir>/<addr>_<name>.c and
//    writes a <outdir>/_index.txt plus a full <outdir>/disasm.txt listing.
//
// usage:
//   analyzeHeadless <proj> <name> -import payload_1.bin \
//     -processor ARM:LE:32:Cortex -loader BinaryLoader \
//     -loader-baseAddr 0x3C000000 -noanalysis \
//     -scriptPath . -postScript DecompileAll.java <outdir> [lo_hex] [hi_hex] [max_functions]
//
// Known limitation: functions whose entry does not start with a PUSH prologue are
// never created (e.g. 0x3C015B18, 0x3C01D3AC) — dump those with thumb_dump.py.
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class DecompileAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outdir = args[0];
        long lo = args.length > 1 ? Long.parseLong(args[1], 16) : 0L;
        long hi = args.length > 2 ? Long.parseLong(args[2], 16) : 0xFFFFFFFFL;
        int maxDecomp = args.length > 3 ? Integer.parseInt(args[3]) : 200000;

        Program prog = currentProgram;
        FunctionManager fm = prog.getFunctionManager();
        Memory mem = prog.getMemory();
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();

        // 1. pick the largest executable block (do not trust getImageBase())
        MemoryBlock blk = null;
        long best = -1;
        for (MemoryBlock b : mem.getBlocks()) {
            if (b.isExecute() && b.getSize() > best) { best = b.getSize(); blk = b; }
        }
        if (blk == null) { println("ERR: no executable memory block found"); return; }
        Address base = blk.getStart();
        int size = (int) blk.getSize();
        println("block=" + blk.getName() + " base=" + base + " size=" + size);

        // 2. force Thumb mode over the whole block (must precede any disassembly)
        Register tmode = prog.getProgramContext().getRegister("TMode");
        if (tmode != null) {
            try {
                prog.getProgramContext().setValue(tmode, base, base.add(size - 1),
                        BigInteger.ONE);
                println("TMode=1 set over the whole block");
            } catch (Exception e) {
                println("TMode already set / not changeable: " + e);
            }
        } else {
            println("WARN: no TMode register on this processor");
        }

        byte[] raw = new byte[size];
        mem.getBytes(base, raw);

        // 3. collect PUSH prologues (T1: 1011 010x, T2: 0xE92D)
        List<Long> pros = new ArrayList<Long>();
        for (int off = 0; off + 3 < size; off += 2) {
            int b0 = raw[off] & 0xFF;
            int b1 = raw[off + 1] & 0xFF;
            if ((b1 & 0xFE) == 0xB4) pros.add(Long.valueOf(off));          // push {..}
            else if (b0 == 0x2D && b1 == 0xE9) pros.add(Long.valueOf(off)); // push.w {..}
        }
        println("candidate prologues: " + pros.size());

        int made = 0;
        int k = 0;
        for (Long off : pros) {
            Address a = base.add(off.longValue());
            if (fm.getFunctionAt(a) != null) continue;
            try {
                new ArmDisassembleCommand(a, null, true).applyTo(prog, mon);
                if (new CreateFunctionCmd(a).applyTo(prog, mon)) made++;
            } catch (Exception e) { /* skip bad candidates */ }
            k++;
            if (k % 20000 == 0) println("  scan " + k + "/" + pros.size() + " made=" + made);
        }
        println("functions created=" + made + " total=" + fm.getFunctionCount());

        File od = new File(outdir);
        od.mkdirs();

        // 4a. full linear listing, handy for grepping in an editor
        PrintWriter dpw = new PrintWriter(new OutputStreamWriter(
                new FileOutputStream(new File(od, "disasm.txt")), "UTF-8"));
        long n = 0;
        for (Instruction ins : prog.getListing().getInstructions(true)) {
            dpw.println(ins.getAddress() + "  " + ins.toString());
            n++;
        }
        dpw.close();
        println("disasm.txt lines=" + n);

        // 4b. decompile each function in range
        DecompInterface di = new DecompInterface();
        di.setOptions(new DecompileOptions());
        if (!di.openProgram(prog)) { println("ERR: could not open decompiler"); return; }

        int count = 0;
        int failed = 0;
        StringBuilder idx = new StringBuilder();
        for (Function f : fm.getFunctions(true)) {
            long ep = f.getEntryPoint().getOffset();
            if (ep < lo || ep > hi) continue;
            if (count >= maxDecomp) { println("max decompile count reached"); break; }
            try {
                DecompileResults res = di.decompileFunction(f, 60, mon);
                String c;
                if (res.decompileCompleted()) {
                    c = res.getDecompiledFunction().getC();
                } else {
                    c = "// decompile failed: " + res.getErrorMessage();
                    failed++;
                }
                String nm = f.getName().replace(" ", "_").replace("/", "_");
                String fn = Long.toHexString(ep) + "_" + nm + ".c";
                PrintWriter pw = new PrintWriter(new OutputStreamWriter(
                        new FileOutputStream(new File(od, fn)), "UTF-8"));
                pw.print(c);
                pw.close();
                idx.append(Long.toHexString(ep)).append(" ").append(fn).append("\n");
                count++;
                if (count % 200 == 0) println("  decompiled " + count + " (failed=" + failed + ")");
            } catch (Exception e) {
                println("err " + Long.toHexString(ep) + ": " + e);
            }
        }
        PrintWriter ipw = new PrintWriter(new File(od, "_index.txt"));
        ipw.print(idx.toString());
        ipw.close();
        println("=== " + count + " functions decompiled (failed=" + failed + ") -> " + outdir + " ===");
    }
}

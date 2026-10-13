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
import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

public class DecompileAlias extends GhidraScript {
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outdir = args[0];
        int maxDecomp = args.length > 1 ? Integer.parseInt(args[1]) : 200000;
        Program prog = currentProgram;
        FunctionManager fm = prog.getFunctionManager();
        Memory mem = prog.getMemory();
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();

        MemoryBlock blk = null; long best = -1;
        for (MemoryBlock b : mem.getBlocks())
            if (b.isExecute() && b.getSize() > best) { best = b.getSize(); blk = b; }
        Address base = blk.getStart();
        int size = (int) blk.getSize();
        byte[] raw = new byte[size];
        mem.getBytes(base, raw);
        println("base block " + blk.getName() + " " + base + " size=" + size);

        Register tmode = prog.getProgramContext().getRegister("TMode");
        try { prog.getProgramContext().setValue(tmode, base, base.add(size - 1), BigInteger.ONE); } catch (Exception e) { println("base TMode already set"); }

        long ALIAS = 0x0C000000L;
        Address aliasStart = prog.getAddressFactory().getDefaultAddressSpace().getAddress(ALIAS);
        if (mem.getBlock(aliasStart) == null) {
            mem.createInitializedBlock("ram_cached", aliasStart,
                    new ByteArrayInputStream(raw), size, mon, false);
            MemoryBlock ab = mem.getBlock(aliasStart);
            ab.setRead(true); ab.setWrite(false); ab.setExecute(true);
            println("alias block ram_cached created at " + aliasStart);
        } else {
            println("alias block already present");
        }
        try { prog.getProgramContext().setValue(tmode, aliasStart, aliasStart.add(size - 1), BigInteger.ONE); } catch (Exception e) { println("alias TMode skip: " + e); }

        if (fm.getFunctionCount() < 1000) {
            println("scanning prologues...");
            List<Long> pros = new ArrayList<Long>();
            for (int off = 0; off + 3 < size; off += 2) {
                int b0 = raw[off] & 0xFF, b1 = raw[off + 1] & 0xFF;
                if ((b1 & 0xFE) == 0xB4) pros.add(Long.valueOf(off));
                else if (b0 == 0x2D && b1 == 0xE9) pros.add(Long.valueOf(off));
            }
            int made = 0, k = 0;
            for (Long off : pros) {
                Address a = base.add(off.longValue());
                if (fm.getFunctionAt(a) != null) continue;
                try {
                    new ArmDisassembleCommand(a, null, true).applyTo(prog, mon);
                    if (new CreateFunctionCmd(a).applyTo(prog, mon)) made++;
                } catch (Exception e) { }
                if (++k % 20000 == 0) println("  scan " + k + "/" + pros.size());
            }
            println("functions created=" + made + " total=" + fm.getFunctionCount());
        } else {
            println("functions already present: " + fm.getFunctionCount() + " (skip scan)");
        }

        File od = new File(outdir);
        od.mkdirs();
        PrintWriter dpw = new PrintWriter(new OutputStreamWriter(new FileOutputStream(new File(od, "disasm.txt")), "UTF-8"));
        long n = 0;
        for (Instruction ins : prog.getListing().getInstructions(true)) { dpw.println(ins.getAddress() + "  " + ins.toString()); n++; }
        dpw.close();
        println("disasm.txt lines=" + n);

        DecompInterface di = new DecompInterface();
        di.setOptions(new DecompileOptions());
        di.openProgram(prog);
        int count = 0, failed = 0;
        StringBuilder idx = new StringBuilder();
        for (Function f : fm.getFunctions(true)) {
            long ep = f.getEntryPoint().getOffset();
            if (ep >= 0x0C000000L && ep < ALIAS + size) continue;
            if (count >= maxDecomp) break;
            try {
                DecompileResults res = di.decompileFunction(f, 60, mon);
                String c = res.decompileCompleted() ? res.getDecompiledFunction().getC()
                        : "// decompile failed: " + res.getErrorMessage();
                if (!res.decompileCompleted()) failed++;
                String nm = f.getName().replace(" ", "_").replace("/", "_");
                String fn = Long.toHexString(ep) + "_" + nm + ".c";
                PrintWriter pw = new PrintWriter(new OutputStreamWriter(new FileOutputStream(new File(od, fn)), "UTF-8"));
                pw.print(c); pw.close();
                idx.append(Long.toHexString(ep)).append(" ").append(fn).append("\n");
                count++;
                if (count % 300 == 0) println("  decompile " + count + " (fail=" + failed + ")");
            } catch (Exception e) { println("err " + Long.toHexString(ep) + ": " + e); }
        }
        PrintWriter ipw = new PrintWriter(new File(od, "_index.txt"));
        ipw.print(idx.toString()); ipw.close();
        println("=== " + count + " decompiled (fail=" + failed + ") ===");
    }
}

// DecompileAll.java — post-script Ghidra (Java, natif Ghidra 12)
// 1. scanne les prologues PUSH de l'image -> désassemble + crée les fonctions manquantes
// 2. décompile les fonctions dans [lo, hi] (args hex) vers <outdir>/<addr>_<name>.c
//
// usage:
//   analyzeHeadless <proj> <name> -process payload1.elf -noanalysis \
//     -scriptPath . -postScript DecompileAll.java /root/jbl/decomp_p1 3C010000 3C060000
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileOptions;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.listing.Program;
import ghidra.util.task.ConsoleTaskMonitor;
import java.io.*;
import java.util.ArrayList;
import java.util.List;

public class DecompileAll extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        String outdir = args[0];
        long lo = args.length > 1 ? Long.parseLong(args[1], 16) : 0L;
        long hi = args.length > 2 ? Long.parseLong(args[2], 16) : -1L;

        Program prog = currentProgram;
        FunctionManager fm = prog.getFunctionManager();
        ghidra.program.model.mem.Memory mem = prog.getMemory();
        ConsoleTaskMonitor mon = new ConsoleTaskMonitor();
        Address base = currentProgram.getImageBase();
        ghidra.program.model.mem.MemoryBlock blk = mem.getBlock(base);
        int size = (int) blk.getSize();
        println("image %d bytes @ %s (bloc %s)" .formatted(size, base, blk.getName()));

        byte[] raw = new byte[size];
        int got = mem.getBytes(base, raw);
        println("read " + got + " bytes");

        println("fonctions auto-analyse: " + fm.getFunctionCount());
        int nrange = 0;
        for (Function f : fm.getFunctions(true)) {
            long ep = f.getEntryPoint().getOffset();
            if (ep >= lo && ep <= hi) nrange++;
        }
        println("fonctions dans la plage: " + nrange);

        if (nrange < 100) {
            println("scan des prologues PUSH...");
            List<Long> pros = new ArrayList<>();
            for (int off = 0; off < size - 3; off += 2) {
                int b0 = raw[off] & 0xFF, b1 = raw[off + 1] & 0xFF;
                if ((b1 & 0xFE) == 0xB4) pros.add((long) off);            // push {..} T1
                else if (b0 == 0x2d && b1 == 0xe9) pros.add((long) off);  // push.w T2
            }
            println("prologues: " + pros.size());
            int made = 0, k = 0;
            for (Long off : pros) {
                Address a = base.add(off);
                if (fm.getFunctionAt(a) == null) {
                    try {
                        new ArmDisassembleCommand(a, null, true).applyTo(prog, mon);
                        if (new CreateFunctionCmd(a).applyTo(prog, mon)) made++;
                    } catch (Exception e) { /* ignore */ }
                }
                if (++k % 20000 == 0) println("  scan " + k + "/" + pros.size());
            }
            println("fonctions créées: " + made + " (total " + fm.getFunctionCount() + ")");
        }

        File od = new File(outdir);
        od.mkdirs();

        DecompInterface di = new DecompInterface();
        di.setOptions(new DecompileOptions());
        di.openProgram(prog);

        int count = 0;
        StringBuilder idx = new StringBuilder();
        for (Function f : fm.getFunctions(true)) {
            long ep = f.getEntryPoint().getOffset();
            if (ep < lo || ep > hi) continue;
            try {
                DecompileResults res = di.decompileFunction(f, 90, mon);
                String c = res.decompileCompleted()
                        ? res.getDecompiledFunction().getC()
                        : "// decompile failed: " + res.getErrorMessage();
                String fn = Long.toHexString(ep) + "_" +
                        f.getName().replace(" ", "_").replace("/", "_") + ".c";
                File fo = new File(od, fn);
                try (PrintWriter pw = new PrintWriter(new OutputStreamWriter(
                        new FileOutputStream(fo), "UTF-8"))) {
                    pw.print(c);
                }
                idx.append(Long.toHexString(ep)).append(' ').append(fn).append('\n');
                count++;
                if (count % 100 == 0) println("  decompile " + count + "...");
            } catch (Exception e) {
                println("err " + Long.toHexString(ep) + ": " + e);
            }
        }
        try (PrintWriter pw = new PrintWriter(new File(od, "_index.txt"))) {
            pw.print(idx.toString());
        }
        println("=== " + count + " fonctions décompilées -> " + outdir + " ===");
    }
}

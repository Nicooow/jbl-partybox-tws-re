import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.util.task.ConsoleTaskMonitor;
import java.math.BigInteger;

public class ScanRange extends GhidraScript {
    public void run() throws Exception {
        String[] a = getScriptArgs();
        long s = Long.parseLong(a[0],16);
        long e = Long.parseLong(a[1],16);
        MemoryBlock blk = null; long best = -1;
        for (MemoryBlock b : currentProgram.getMemory().getBlocks())
            if (b.isExecute() && b.getSize() > best) { best = b.getSize(); blk = b; }
        Address base = blk.getStart();
        Register tmode = currentProgram.getProgramContext().getRegister("TMode");
        currentProgram.getProgramContext().setValue(tmode, base, base.add(blk.getSize()-1), BigInteger.ONE);
        println("TMode set over " + base + ".." + base.add(blk.getSize()-1));
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(s);
        Address end = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(e);
        AddressSet set = new AddressSet(start, end);
        new ArmDisassembleCommand(start, set, false).applyTo(currentProgram, new ConsoleTaskMonitor());
        Address cur = start;
        while (cur.compareTo(end) <= 0) {
            Instruction ins = getInstructionAt(cur);
            if (ins == null) { println(cur + "  ??"); cur = cur.add(2); }
            else { println(ins.getAddress() + "  " + ins.toString()); cur = ins.getAddress().add(ins.getLength()); }
        }
    }
}

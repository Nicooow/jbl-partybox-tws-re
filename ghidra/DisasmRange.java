import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.util.task.ConsoleTaskMonitor;
import java.math.BigInteger;

public class DisasmRange extends GhidraScript {
    public void run() throws Exception {
        String[] a = getScriptArgs();
        long s = Long.parseLong(a[0],16);
        long e = Long.parseLong(a[1],16);
        Address start = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(s);
        Address end = currentProgram.getAddressFactory().getDefaultAddressSpace().getAddress(e);
        clearListing(start, end);
        Register tmode = currentProgram.getProgramContext().getRegister("TMode");
        if (tmode != null) {
            try { currentProgram.getProgramContext().setValue(tmode, start, end, BigInteger.ONE); }
            catch (Exception ex) { println("setValue skipped: " + ex); }
        }
        AddressSet set = new AddressSet(start, end);
        new ArmDisassembleCommand(start, set, false).applyTo(currentProgram, new ConsoleTaskMonitor());
        Address cur = start;
        while (cur.compareTo(end) <= 0) {
            Instruction ins = getInstructionAt(cur);
            if (ins == null) { println(cur + "  ????"); cur = cur.add(2); }
            else { println(ins.getAddress() + "  " + ins.toString()); cur = ins.getAddress().add(ins.getLength()); }
        }
    }
}

import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;

public class DiagBlocks extends GhidraScript {
    @Override
    public void run() throws Exception {
        println("imageBase=" + currentProgram.getImageBase());
        println("min=" + currentProgram.getMemory().getMinAddress());
        println("max=" + currentProgram.getMemory().getMaxAddress());
        for (MemoryBlock b : currentProgram.getMemory().getBlocks()) {
            println("bloc: name=" + b.getName() + " start=" + b.getStart()
                    + " size=" + b.getSize() + " addr=" + b.getAddressSpace());
        }
    }
}

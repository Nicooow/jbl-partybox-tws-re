# DecompileAll.py — post-script Ghidra (Jython, headless)
# 1. passe tout le programme en désassemblage Thumb
# 2. crée des fonctions aux prologues PUSH {.., lr} non couverts
# 3. décompile chaque fonction dans <outdir>/<addr>_<name>.c + un index
#
# usage headless:
#   analyzeHeadless /tmp/proj JBL -import payload1.elf \
#     -processor ARM:LE:32:Cortex \
#     -postScript DecompileAll.py /tmp/decomp \
#     -scriptPath <dossier de ce script>
import os
from ghidra.app.cmd.disassemble import ArmDisassembleCommand
from ghidra.app.cmd.function import CreateFunctionCmd
from ghidra.app.decompiler import DecompInterface, DecompileOptions
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.program.model.address import AddressSet

args = getScriptArgs()
outdir = args[0] if args else "decompiled"
os.makedirs(outdir, exist_ok=True)

prog = currentProgram
fm = prog.getFunctionManager()
mem = prog.getMemory()
mon = ConsoleTaskMonitor()
base = mem.getMinAddress().getOffset()
size = mem.getMaxAddress().getOffset() - base + 1
raw = bytes(java.array('b', [0]) and mem.getBytes(mem.getMinAddress(), size))

print("/thumb-disassemble %d bytes..." % size)
ea = mem.getMinAddress()
total = 0
for off in range(0, size - 1, 2):
    h = raw[off] | (raw[off+1] << 8)
    a = ea.add(off)
    if getInstructionAt(a) is None and not listing.getInstructionAt(a):
        try:
            cmd = ArmDisassembleCommand(a, None, True)
            ok = cmd.applyTo(mon)
            if ok: total += 1
        except Exception:
            pass
print("instructions: %d" % total)

print("creation de fonctions aux prologues PUSH...")
made = 0
for off in range(0, size - 3, 2):
    h = raw[off] | (raw[off+1] << 8)
    is_push_lr16 = (h & 0xFF00) == 0xB500 or (h & 0xFE00) == 0xB400
    is_push_w = raw[off] in (0x2d, 0xed) and raw[off+1] in (0xe9,)  # push.w {..,lr} approx: e92d
    if raw[off] == 0x2d and raw[off+1] == 0xe9:
        is_push_w = True
    else:
        is_push_w = False
    if is_push_lr16 or is_push_w:
        a = ea.add(off)
        if fm.getFunctionAt(a) is None:
            cmd = CreateFunctionCmd(a)
            if cmd.applyTo(mon):
                made += 1
print("fonctions créées: %d (total %d)" % (made, fm.getFunctionCount()))

di = DecompInterface()
di.setOptions(DecompileOptions())
di.openProgram(prog)

index = []
count = 0
for f in fm.getFunctions(True):
    try:
        res = di.decompileFunction(f, 90, mon)
        if res.decompileCompleted():
            c = res.getDecompiledFunction().getC()
        else:
            c = "// decompile failed: %s" % res.getErrorMessage()
        name = "%x_%s.c" % (f.getEntryPoint().getOffset(),
                            f.getName().replace(" ", "_").replace("/", "_"))
        with open(os.path.join(outdir, name), "w") as fh:
            fh.write("// function %s @ %s\n" % (f.getName(), f.getEntryPoint()))
            fh.write(c)
        index.append("%-40s %s" % (hex(f.getEntryPoint().getOffset()), name))
        count += 1
    except Exception as e:
        print("erreur decomp %s: %s" % (f.getEntryPoint(), e))

with open(os.path.join(outdir, "_index.txt"), "w") as fh:
    fh.write("\n".join(index) + "\n")
print("=== %d fonctions décompilées dans %s ===" % (count, outdir))

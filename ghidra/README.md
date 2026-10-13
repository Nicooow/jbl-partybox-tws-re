# Full decompilation with Ghidra (WSL) + browsing in VSCode

The Bluetooth module firmware (`payload_1.bin`, 3.1 MB — ARM Cortex-M, XIP at `0x3C000000`)
and the front-panel MCU firmware (`payload_4.bin`, 47 KB — Cortex-M0 at `0x08002000`) are plain
ARM Thumb code. This kit turns them into fully decompiled C you can browse in VSCode.

## 1. WSL setup (once)

```bash
sudo apt install -y openjdk-21-jdk unzip python3 git
# Ghidra 12.1.4 was used here. Ghidra 12 dropped Jython, hence the Java scripts.
wget https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/ghidra_12.1.4_PUBLIC_20250826.zip -O ghidra.zip
unzip ghidra.zip -d /opt
export GHIDRA_INSTALL_DIR=/opt/ghidra_12.1.4_PUBLIC
```

## 2. Headless analysis + full decompilation

Import the **raw blob**, not the ELF wrapper (see `make_elf.py` for the wrapper and why it is
the wrong tool here):

```bash
mkdir -p /root/jbl /root/ghidra_proj
cp payload_1.bin /root/jbl/
$GHIDRA_INSTALL_DIR/support/analyzeHeadless /root/ghidra_proj JBL \
    -import /root/jbl/payload_1.bin \
    -processor ARM:LE:32:Cortex -loader BinaryLoader -loader-baseAddr 0x3C000000 -noanalysis \
    -scriptPath /root/jbl -postScript DecompileAll.java /root/jbl/decomp_p1
```

(10–40 min on `payload_1` — it is 3 MB. Same command with `payload_4.bin` and
`-loader-baseAddr 0x08002000` takes a couple of minutes.)

Then in VSCode **on Windows**: `File > Open Folder` → `\\wsl$\Ubuntu\root\jbl\decomp_p1`.
Each function is one decompiled `.c` file, with a `_index.txt` sorted by address, plus a full
`disasm.txt` listing. Global search (Ctrl+Shift+F) works across the whole corpus.

## Three pitfalls that will cost you an afternoon

1. **`getImageBase()` returns 0.** With a `BinaryLoader` import the image lands in a block named
   `ram` at the requested `-loader-baseAddr`, but the program's image base is 0 — so
   `mem.getBlock(getImageBase())` returns `null` and your script dies with an NPE. Always locate
   the executable block by scanning `getMemory().getBlocks()`.
2. **Thumb mode is not automatic.** Without `TMode=1` the ARM disassembler decodes Thumb bytes as
   garbage. Set it with
   `getProgramContext().setValue(getRegister("TMode"), start, end, BigInteger.ONE)` **before any
   disassembly** — it only succeeds on a fresh import, or after `clearListing` (otherwise Ghidra
   throws `ContextChangeException: Context register change conflicts with one or more instructions`).
3. **The image is aliased at two addresses.** `0x0C000000` and `0x3C000000` map the same bytes
   (Δ `0x30000000`). Absolute *code* pointers stored in tables and literal pools use the
   `0x0C01…` form (e.g. `0x0C014EA5` == `0x3C014EA5` == `FUN_3c014ea4|1`) while *string* pointers
   use `0x3C05…`. If you only map one of them, every absolute jump/callback table is
   unresolvable and the decompiler prints "Bad instruction - Truncating control flow".
   `DecompileAlias.java` creates the second block before decompiling.

## 4. Exploration tips

- Grep for `TWS_BESAUD`, `SOURCE=%d`, `STANDBY=%d`, `0xbe59` to land on the functions already
  identified (`parse_cmd` @ `0x3C01A1F4`, RX dispatcher @ `0x3C01A8A8`, `build_cmd`/`FUN_3c019FE0`,
  event loop @ `0x3C012E84`).
- Also useful: search the TX send buffer `0x200329E8` and the shared context `0x2002F31C`.
- Ghidra's decompilation is good on this binary: the 18 BESAUD handlers in `parse_cmd` come out as
  a readable `switch`.
- Jump-table base rule for `TBH`/`TBB`: **base = address of the TBH instruction + 4** (do not align
  it down — that shifts every case target by −2).
- Functions that do not start with a `PUSH` prologue are never created (`0x3C015B18`, `0x3C01D3AC`,
  `0x3C015020`). Dump those directly with
  `python3 thumb_dump.py payload_1.bin 3C000000 <start_hex> <end_hex>`.
- For SPHE `payload_0` (ARM9, **encoded**): this kit is useless until the encoding is broken —
  and if a NOR dump ever shows up, the Ghidra import will be `ARM:LE:32:ARMv5` at base `0x0`
  (adjust as needed).

## 5. REA under WSL?

The REA MCP server runs on the Windows side and its Windows Ghidra bridge only accepts x86/x64 PE
files — no ARM decompiler provider here. Two options:

- **Start the ZCode session from WSL**: REA then runs on Linux, where its Ghidra provider accepts
  ARM ELF files (`GHIDRA_INSTALL_DIR` from WSL) — and you can ask it for on-demand decompilations
  during the conversation;
- or just use this headless kit (enough to explore everything offline).

## Files

| file | purpose |
|---|---|
| `DecompileAll.java` | prologue scan → create functions → decompile all in range |
| `DecompileAlias.java` | same, plus maps the `0x0C000000` cached alias (needed for jump tables) |
| `DiagBlocks.java` | dumps the program's memory blocks (debugging imports) |
| `DisasmRange.java` / `ScanRange.java` | disassemble one address range to stdout |
| `thumb_dump.py` | standalone Capstone Thumb listing for any range (no Ghidra needed) |
| `eventloop_tables.py` | decodes the app-event dispatch tables |
| `make_elf.py` | wraps a raw payload in an ARM ELF (for GUI imports) |

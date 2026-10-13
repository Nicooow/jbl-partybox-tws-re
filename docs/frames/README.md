# BESAUD frame reference — all 15 frames emitted by the speaker

Complete, code-derived documentation of every BESAUD command the JBL PartyBox gen-1
speaker (BES2000IK module, `payload_1.bin`) can **emit**, plus its receive-side handler.

Frame envelope: `[type][cmd16 LE][payload…]` — type `0x80` = command, `0x81` = ack/response,
`0x83` = SBC audio. Payloads are normally a fixed **18 bytes**, so a frame is 19 bytes on the wire
(`0x80` + 18). Outbound frames are all built by `tws_besaud_build_cmd` = `FUN_3c019fe0(buf, len,
timeout_ms)`, which is **gated on a live session handle `*(u32*)(ctx+0x310) != 0`** — with no real
TWS session nothing is ever sent (this is why injected frames on an unbound RFCOMM link get no ack).

The command space is closed: the RX dispatcher only knows types `0x80/0x81/0x83`, and the inbound
`parse_cmd` switch does `subs r3,#0x100; cmp r3,#0x11; bhi default` — so ids are exactly
`0x0100`–`0x0111`. **`0x0100`, `0x0102` and `0x010B` are never emitted** (receive-only).

| Frame | Name | Emit builder | Event | Inbound handler |
|---|---|---|---|---|
| [`0x0101`](0x0101.md) | TWS state broadcast (14-byte) | `FUN_3c01ad18` | 0x01 | `0x3C01A2A0` |
| [`0x0103`](0x0103.md) | partial teardown request | `FUN_3c01af50` | 0x0A | `0x3C01A232` |
| [`0x0104`](0x0104.md) | playback-action broadcast | `FUN_3c01af7c` | 0x0E | `0x3C01A2CC` |
| [`0x0105`](0x0105.md) | volume + action sync | `FUN_3c01aca8` | 0x02 | `0x3C01A2D6` |
| [`0x0106`](0x0106.md) | link / stream state sync | `FUN_3c01ace4` | 0x03 | `0x3C01A306` |
| [`0x0107`](0x0107.md) | audio-stream configuration | `FUN_3c01ad94` | 0x04 | `0x3C01A34E` |
| [`0x0108`](0x0108.md) | channel assignment (committed) | `FUN_3c01ae28` | 0x11 | `0x3C01A3D2` |
| [`0x0109`](0x0109.md) | remote disconnect request | `FUN_3c01afa8` | 0x12 | `0x3C01A3F2` |
| [`0x010A`](0x010A.md) | `SYNC_REM_KEY_STATUS` | `FUN_3c01afd4` | 0x14 | `0x3C01A428` |
| [`0x010C`](0x010C.md) | stream/link-config confirm | `FUN_3c01a058`, `FUN_3c01a0f0` | — | `0x3C01A468` |
| [`0x010D`](0x010D.md) | engine reset / abort | `FUN_3c01b008` | — | `0x3C01A47E` |
| [`0x010E`](0x010E.md) | **SOURCE** selector → SPHE UART | `FUN_3c01ae68` | 0x18 | `0x3C01A4A2` |
| [`0x010F`](0x010F.md) | **STANDBY** → SPHE UART | `FUN_3c01aea4` | 0x19 | `0x3C01A4B0` |
| [`0x0110`](0x0110.md) | channel assignment (active-only) | `FUN_3c01aed4` | 0x1A | `0x3C01A4C8` |
| [`0x0111`](0x0111.md) | `PST` flag | `FUN_3c01af10` | 0x1B | `0x3C01A272` |

## Cross-cutting findings

**Byte ↔ channel mapping** (authoritative, from the code — the receive side **mirrors** the value):
wire `03` → Right, `04` → Left, `01`/`02`/anything else → Stereo. The internal mode is stored at
`ctx+0x19` (active) and `ctx+0x18` (negotiated), and `FUN_3C015B18` logs it as `TWSLR=S/L/R`.

**Shared state block** `ctx = 0x2002F31C`:

| offset | meaning |
|---|---|
| `ctx+8` | live link role (1/2; 3/4 after teardown) |
| `ctx+9` | committed link role (1 = initiator/master, 2 = follower) |
| `ctx+0x11` | teardown in progress |
| `ctx+0x15` | playback suppression flag (raised by `0x0104` action code 9, cleared by teardown) |
| `ctx+0x16` | peer state byte (from `0x0101`/`0x0106`) |
| `ctx+0x18` / `ctx+0x19` | negotiated / active channel mode |
| `ctx+0x291` | one-shot "0x010C reply pending" |
| `ctx+0x304` | synced volume level (u16, clamped 0…32) |
| `ctx+0x306`, `ctx+0x307` | state / `PST` flags |
| `ctx+0x310` | **session handle — every send is gated on it** |

Device role is read by `func_0x3c01d3ac` = `*(u8*)(0x200351EC + 5)` (1 = primary/master).
Other globals referenced by these frames: `0x2002A82C` (audio state byte, 3/9), `0x2002A840`
(config word A, master⇄follower), `0x2002A848` (clamped volume byte), `0x2002ABE0`
(playback-active flag), `0x20031281` (external arm flag read by `0x0111`).

**Live-injection confidence.** Only `0x0104` (play/pause, code 6), `0x0105` (volume) and `0x0108`
(channel) have been confirmed on real hardware; the rest are **static analysis only** — each page
states its own confidence and unknowns.

## Evidence base

Firmware `extracted/payload_1.bin`, Thumb, linked at `0x3C000000` (file offset = VA − 0x3C000000),
also mapped at `0x0C000000` (cached alias, Δ 0x30000000 — absolute code pointers use the `0x0C01…`
form). All claims come from the Ghidra decompilation in `../../decomp/` plus targeted Thumb
disassembly (`ghidra/thumb_dump.py`). Reproduce any address with:

```bash
py ghidra/thumb_dump.py extracted/payload_1.bin 3C000000 <start_hex> <end_hex>
```

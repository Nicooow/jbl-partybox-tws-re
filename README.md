# Reverse Engineering — JBL PartyBox 100/200/300 TWS link

How the wireless TWS link between two JBL PartyBox speakers works, and how to make a
Linux box impersonate a PartyBox and speak the protocol.

Tested on: **JBL PartyBox 200**, firmware v37 (`Harman_G1.HUI`, hardware gen 1, 2019).
The PartyBox 300 shares the same main board/firmware; the PartyBox 100 is close enough
that the pairing rules below apply too.

> Everything here was done on hardware I own, for interoperability and curiosity.

## TL;DR

Two PartyBoxes in TWS mode talk over a **Bluetooth Classic L2CAP channel on PSM 51 (0x33)**
using a simple proprietary protocol ("BESAUD"):

```
[type byte] [command: u16 little-endian] [payload...]
  0x80 = command, 0x81 = response/ack, 0x83 = SBC audio stream
```

A Linux box with BlueZ can impersonate a PartyBox: set the right Bluetooth **name**,
make it discoverable/pairable, and run a small Python server listening on PSM 51.
You get play/pause, volume and stereo-channel control injected into the speaker.
That's about it — lights and bass boost are handled by the main SoC and never cross
the TWS link.

## 1. Becoming a compatible receiver (Linux setup)

The PartyBox matches the **Bluetooth name** of the peer, per model:

| Your speaker | Receiver name must be |
|---|---|
| PartyBox 100 | `JBL Partybox 100` |
| PartyBox 200 | `JBL Partybox 200` **or** `JBL Partybox 300` |
| PartyBox 300 | `JBL Partybox 200` **or** `JBL Partybox 300` |

Setup on Linux (BlueZ):

```bash
# name matters — set it per the table above
sudo btmgmt name "JBL Partybox 200"
# look like a speaker (Class of Device: Audio/Video > Loudspeaker)
sudo btmgmt class 4 20
# be visible and accept pairing (Secure Simple Pairing, Just Works)
bluetoothctl discoverable on
bluetoothctl pairable on
bluetoothctl agent on
bluetoothctl default-agent
```

Notes:
- The speaker pairs with **Secure Simple Pairing, Just Works** (NoInputNoOutput).
  Keep an agent registered in a *running* bluetoothctl session, otherwise the host
  replies "Pairing Not Allowed" and the speaker walks away.
- The speaker broadcasts a small non-connectable **BLE beacon** (company ID `0xBE59`,
  18-byte EIR: flags + manufacturer payload `[status][6 bytes]` + appearance `0xDAFE`).
  It looks like a TWS status beacon. In practice, the recipe above (name + Classic
  discoverable) was enough to get connected; we did not need to spoof the beacon.
- Known quirk on some Broadcom-based SBCs (e.g. Khadas VIM3, AP6398S): `hcitool cmd
  08 06 ...` (LE Set Advertising Parameters) needs **15 bytes** on this firmware
  (an extra trailing filter-policy byte) while the spec says 14. If you don't need
  the LE beacon, ignore it.

## 2. What happens when the speaker connects (btmon view)

```
Connect Request (ACL) from the PartyBox
→ Accept, Simple Pairing (Just Works) → Link Key → Encryption (E0)
→ L2CAP Connection Request: PSM 51 (0x0033)   <-- the proprietary TWS channel
→ (also tries SDP lookup, and RFCOMM channel 1 on some flows)
```

The speaker **initiates** the Classic connection when it is in TWS pairing mode and
finds a peer whose name matches. Once connected and bonded, it opens PSM 51 and
starts speaking the protocol below.

## 3. Frame format ("BESAUD")

Every frame on PSM 51:

```
offset 0   : type byte
             0x80 = command (parsed by the receiver's parse_cmd)
             0x81 = response/ack
             0x83 = audio stream (SBC)
offset 1..2: command id, u16 little-endian (valid: 0x0100..0x0111)
offset 3.. : payload (control frames are 16 bytes of payload → 19-byte frames)
```

Every command is acknowledged with an 18-byte frame: `0x81 + echoed cmd + status
byte (0x00 = ok) + a 16-byte live state snapshot` (some bytes of the snapshot change
with the playback state).

Known command ids — decoded from the firmware (`parse_cmd` @ firmware offset 0x1a1f4:
18-case table) **and** verified on a live fake-peer session:

| Cmd | Payload (after the cmd16) | Meaning |
|---|---|---|
| `0x0100` | byte @0 | stored in speaker state |
| `0x0101` | u32 @0, u32 @4, u32 @8, u16 @12, byte @15 | full state broadcast (14 useful bytes) |
| `0x0102` | — | no-op (ack only) |
| `0x0103` | — | TWS teardown (state-gated) |
| `0x0104` | u32 @0 = action code | **0x06 = play/pause toggle (injection confirmed)**; posted as app-event 0x0F — other action codes untested |
| `0x0105` | u32 @2, u32 @6, u32 @10, u16 @14 | player update; observed volume updates — **volume injection confirmed** (value in the low byte) |
| `0x0106` | byte @0, byte @3, u32 @6 | state sync (`02 00 00 ff ...` seen) |
| `0x0107` | bytes @0/@1/@3/@6, u32 @8, u32 @12 | stream config; u32 @12 = sample rate (0xAC44 = 44100) |
| `0x0108` | byte @0: 02 = L+R, 03 = Left, 04 = Right | **stereo channel selector** |
| `0x0109` | — | "remote want to disconnect the TWS" |
| `0x010A` | u32 @0 = key id, byte @4 = flag (press/release) | `SYNC_REM_KEY_STATUS`; acks OK but no visible action for ids 0x00–0x3F |
| `0x010B` | u32 @0, u32 @4 | forwarded to an unresolved setter (second flash bank) |
| `0x010C` | — | triggers a conditional internal action |
| `0x010D` | — | conditional action (internal states 1 / 0x10) |
| `0x010E` | byte @0 = source id | **SOURCE selector** — relayed to the main SoC as `SOURCE=%d` over the internal UART |
| `0x010F` | byte @0 = 0/1 | **STANDBY** — relayed to the main SoC as `STANDBY=%d` over the internal UART |
| `0x0110` | byte @0: 02/03/04 | stereo channel selector (duplicate encoding of 0x0108) |
| `0x0111` | byte @0 | forwarded to an internal function (state-gated) |

Notable: commands `0x010E` and `0x010F` are **relayed by the Bluetooth module to the
main SoC over the internal UART** (`SOURCE=%d` / `STANDBY=%d` — the same control API
used between the two chips), so a fake peer can reach beyond the Bluetooth module.

## 4. Audio frames (0x83) — not fully reversed

When audio plays, the master re-streams it to the peer over the same channel:
606-byte chunks starting with `0x83`, then a ~10-byte header, then **raw SBC frames**
(syncword `0x9C`). The RX handler in the firmware skips a 10/11-byte header and
feeds the rest to the audio pipeline.

We did not reverse the header (sequence numbers? sync fields?) any further.
Note: with a fake peer that doesn't do the real TWS audio handshake, the music on
the speaker can stutter — two audio streams share the speaker's radio (phone →
speaker A2DP, speaker → peer re-stream), and some TWS flow-control is likely missing.

## 5. What you can and cannot control

Works over this channel (injected from the fake peer):

- **play/pause toggle** : `80 04 01 06 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00`
- **volume level NN**  : `80 05 01 NN 00 02 00 00 00 00 00 00 00 00 00 00 00 00 00` (NN ≈ 0x00–0x19)
- **stereo channel**   : `80 08 01 02/03/04 00 00 00 00 00 00 00 00 00 00 00 00 00 00`

Does **not** work / not reachable:

- **Lights, bass boost, IR, source selection behind the switch** — these are handled
  locally by the main SoC (a Sunplus SPHE8107) and never cross the TWS link.
  (On our unit, the LEDs are driven by a front-panel STM32F030 that receives
  `55 xx ...` frames from the SPHE over a private UART — a separate protocol,
  out of scope here.)
- `0x010A` key sync: acked but no physical action was obtained with key ids 0x00–0x3F
  (press/release). Either the payload format differs or it only mirrors button state
  for display.

## 6. The server (Python)

`tws_server.py` — listens on PSM 51 + RFCOMM 1, dumps everything, and gives you
interactive commands (play/pause, volume, channel, raw frames). Run as root:

```bash
sudo python3 tws_server.py
```

Then power-cycle the speaker and start TWS pairing mode; it should connect to your
box (name matching) and the frames will scroll. Type `help` in the console.

## 7. Firmware versions

- The gen-1 command table is **identical** across firmware versions: v37 and 34.17.42
  have byte-identical `parse_cmd` dispatch tables (all 18 entries, zero delta).
  The protocol described here is the complete set for generation 1.
- Newer firmware (v37) **expanded** the internal control API vs 34.17.42: the
  `GAIN=`, `LR=`, `BYPASS=`, `SLEEP=`, `I2SIN=` UART commands were added
  (`STANDBY`, `SOURCE`, `DEMO`, `MUTE`, `AMP` existed before).
- The **generation 2** hardware (`Harman_G15.HUI`) runs a different **build** of the same
  firmware family: its BT firmware image is plain code too, contains the same UART relay
  API (`SOURCE=%d`, `STANDBY=%d`, `DEMO=%d`, `AMP=%d`), the same `besaud` functions and a
  `build_cmd` that is **nearly identical** to gen-1's (session handle at the same state
  offset `+0x310`, type byte, same 96-byte length limit). Since gen-1 and gen-2
  PartyBoxes pair with each other over TWS, the wire protocol is the same — only the
  build addresses and some log strings differ. The gen-2 `parse_cmd` dispatch was also
  located: same envelope, but commands are **single-byte ids 1..18** (18-case table)
  instead of gen-1's 16-bit `0x0100..0x0111`; only ~7 ids have real handlers
  (playback control, value set, TWS teardown, one heavily state-gated action). The
  gen-2 build also adds an `ATS=` UART command not present in gen-1.

## 8. Conclusion

Honestly? Very little practical use — you get remote play/pause, volume and a stereo
side selector for a speaker that already has buttons. But it was a fun ride: a
proprietary update container, a three-chip architecture, an obfuscated TWS protocol,
and a Bluetooth stack that happily accepts a Linux box wearing a JBL name tag as
its new best friend.

## Files

- `tws_server.py` — the fake TWS peer / dump server / remote.

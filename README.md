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

Known command ids observed on the wire (from a live fake-peer session) or decoded
in the firmware (`parse_cmd` @ firmware offset 0x1a1f4, a 17-case switch):

| Cmd | Meaning | Notes |
|---|---|---|
| `0x0101` | state broadcast | payload[0] = 0x03 seen at connect |
| `0x0103` | remote disconnect request | handled only in some TWS states |
| `0x0104` | payload[0] = 0x06 → **PLAY/PAUSE toggle** | injection confirmed |
| `0x0105` | [0]=value, [2]=action | action 0x02 = **set volume** (injection confirmed, value = volume level), action 0x01 seen on play |
| `0x0106` | state sync | `02 00 00 ff ...` seen |
| `0x0107` | stream config | contains sample rate as u16 LE (0xAC44 = 44100) |
| `0x0108` | **stereo channel selector** | payload[0]: 02 = L+R, 03 = Left only, 04 = Right only |
| `0x010A` | `SYNC_REM_KEY_STATUS` | u32 key @+0, flag byte @+4; acks fine but no visible action was obtained (see §6) |
| `0x010E` | stream event | seen around play |
| others   | 0x0102, 0x0109, 0x010B–0x010D, 0x010F–0x0111 | not identified |

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

## 7. Conclusion

Honestly? Very little practical use — you get remote play/pause, volume and a stereo
side selector for a speaker that already has buttons. But it was a fun ride: a
proprietary update container, a three-chip architecture, an obfuscated TWS protocol,
and a Bluetooth stack that happily accepts a Linux box wearing a JBL name tag as
its new best friend.

## Files

- `tws_server.py` — the fake TWS peer / dump server / remote.

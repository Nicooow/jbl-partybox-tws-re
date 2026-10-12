#!/usr/bin/env python3
"""
tws_server.py — fake JBL PartyBox TWS peer (Linux/BlueZ)

Listens on L2CAP PSM 51 (0x33) and RFCOMM channel 1, dumps every frame the
speaker sends, and lets you inject play/pause, volume and stereo-channel
commands once the speaker connects.

Run as root:
    sudo python3 tws_server.py

Then power-cycle the speaker and start TWS pairing mode on it.
Your adapter's Bluetooth name must match the speaker model
(see README): e.g. "JBL Partybox 200" for a PartyBox 200.

Interactive commands:
    play / pause      playback toggle (cmd 0x0104 / 0x06)
    vol <0-25>        set volume (cmd 0x0105 / action 0x02)
    ch <2|3|4>        stereo channels: 2=L+R, 3=Left, 4=Right (cmd 0x0108)
    key <hex> [flag]  SYNC_REM_KEY_STATUS (cmd 0x010A), flag 1=press 0=release
    ksweep [N]        sweep key ids 0x00..N (press+release), watch the speaker
    s <hex>           send raw frame on PSM 51
    c                 active connections
    help / quit
"""
import socket, sys, threading, time, subprocess, re, collections

# ---------------------------------------------------------------- adapter addr
def local_bdaddr():
    try:
        out = subprocess.run(["hciconfig", "hci0"], capture_output=True, text=True).stdout
        return re.search(r"BD Address: ([0-9A-F:]{17})", out).group(1)
    except Exception:
        return "00:00:00:00:00:00"

BD = local_bdaddr()
LOGFILE = "tws_frames.log"

log_lock = threading.Lock()
def log(m):
    with log_lock:
        line = f"[{time.strftime('%H:%M:%S')}] {m}"
        print(line, flush=True)
        try:
            with open(LOGFILE, "a") as f:
                f.write(line + "\n")
        except Exception:
            pass

def hexdump(d):
    for i in range(0, len(d), 16):
        c = d[i:i+16]
        log("    {:04x}: {:<48} {}".format(
            i, " ".join(f"{b:02x}" for b in c),
            "".join(chr(b) if 32 <= b < 127 else "." for b in c)))

conns = {}  # tag -> socket

def send_l2cap(data):
    c = conns.get("L2CAP/51")
    if not c:
        log("!! no L2CAP/51 connection"); return
    c.send(data)
    log(f">> L2CAP/51 {data.hex(' ')}")

# ------------------------------------------------------------ frame builders
def f_playpause():                       # 0x0104 / action 0x06 : play/pause toggle
    return bytes([0x80, 0x04, 0x01, 0x06]) + b"\x00" * 15
def f_volume(level):                     # 0x0105 / action 0x02 : set volume
    return bytes([0x80, 0x05, 0x01, level & 0xFF, 0x00, 0x02]) + b"\x00" * 13
def f_channel(mode):                     # 0x0108 : 2=L+R, 3=L, 4=R
    return bytes([0x80, 0x08, 0x01, mode & 0xFF]) + b"\x00" * 15
def f_key(key, flag):                    # 0x010A : key sync (u32 key, flag byte)
    return bytes([0x80, 0x0A, 0x01]) + key.to_bytes(4, "little") + bytes([flag]) + b"\x00" * 11

# ---------------------------------------------------------------- pump
def pump(conn, addr, tag):
    log(f"+++ {tag} connected from {addr}")
    while True:
        try:
            d = conn.recv(2048)
        except Exception:
            break
        if not d:
            log(f"--- {tag} closed by speaker"); break
        if d[0] == 0x83:                       # audio: drain fast, don't spam
            log(f"<< {tag} AUDIO {len(d)} bytes")
        else:
            log(f"<< {tag} {len(d)} bytes: {d.hex(' ')}")
            for i in range(0, len(d), 16):
                c = d[i:i+16]
                log("    {:04x}: {:<48} {}".format(
                    i, " ".join(f"{b:02x}" for b in c),
                    "".join(chr(b) if 32 <= b < 127 else "." for b in c)))
    try: conn.close()
    except Exception: pass
    conns.pop(tag, None)

def l2cap_server():
    s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_SEQPACKET, socket.BTPROTO_L2CAP)
    s.bind((BD, 0x0033)); s.listen(2)
    log("listening: L2CAP PSM 51")
    while True:
        c, a = s.accept()
        conns["L2CAP/51"] = c
        threading.Thread(target=pump, args=(c, a, "L2CAP/51"), daemon=True).start()

def rfcomm_server():
    s = socket.socket(socket.AF_BLUETOOTH, socket.SOCK_STREAM, socket.BTPROTO_RFCOMM)
    s.bind((BD, 1)); s.listen(2)
    log("listening: RFCOMM channel 1")
    while True:
        c, a = s.accept()
        conns["RFCOMM/1"] = c
        threading.Thread(target=pump, args=(c, a, "RFCOMM/1"), daemon=True).start()

# ---------------------------------------------------------------- console
def ksweep(limit=0x1F):
    print(f"=== key sweep 0x00..0x{limit:02X} — watch the speaker ===", flush=True)
    for k in range(limit + 1):
        print(f"  >>> key 0x{k:02X} press", flush=True)
        send_l2cap(f_key(k, 1)); time.sleep(1.2)
        print(f"  >>> key 0x{k:02X} release", flush=True)
        send_l2cap(f_key(k, 0)); time.sleep(1.2)
    print("=== sweep done ===", flush=True)

def help():
    print("""commands:
  play / pause     playback toggle        vol <0-25>     set volume
  ch <2|3|4>       stereo channels        key <hex> [f]  key sync (f: 1 press / 0 release)
  ksweep [N]       sweep key ids 0x00..N  s <hex>        raw frame on PSM 51
  c                active connections     help / quit""")

def console():
    while True:
        try:
            line = input("tws> ").strip()
        except (EOFError, KeyboardInterrupt):
            sys.exit(0)
        if not line: continue
        p = line.split()
        try:
            if p[0] == "play" or p[0] == "pause":
                send_l2cap(f_playpause())
            elif p[0] == "vol" and len(p) > 1:
                send_l2cap(f_volume(int(p[1])))
            elif p[0] == "ch" and len(p) > 1:
                send_l2cap(f_channel(int(p[1])))
            elif p[0] == "key" and len(p) > 1:
                flag = int(p[2]) if len(p) > 2 else 1
                send_l2cap(f_key(int(p[1], 16), flag))
            elif p[0] == "ksweep":
                ksweep(int(p[1], 16) if len(p) > 1 else 0x1F)
            elif p[0] == "s" and len(p) > 1:
                send_l2cap(bytes.fromhex("".join(p[1:])))
            elif p[0] == "c":
                print("connections:", list(conns) or "none")
            elif p[0] == "help":
                help()
            elif p[0] == "quit":
                sys.exit(0)
            else:
                help()
        except Exception as e:
            print("error:", e)

if __name__ == "__main__":
    print(f"adapter BD address: {BD}")
    print(f"frames logged to ./{LOGFILE}")
    help()
    threading.Thread(target=l2cap_server, daemon=True).start()
    rfcomm_server()

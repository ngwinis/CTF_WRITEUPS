#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os, sys, time, random, socketserver, hashlib, argparse

# ===== Config (ENV/CLI) =====
def env_str(k, d): return os.environ.get(k, d)
def env_int(k, d): return int(os.environ.get(k, str(d)))
def env_flt(k, d): return float(os.environ.get(k, str(d)))

FLAG       = env_str("FLAG", "PTITCTF{????????????????????}")
BITS       = 20
MOD        = 1 << BITS
ROUND_CONST= 0x9E377

# ===== wcwidth =====
try:
    from wcwidth import wcswidth
except Exception:
    def wcswidth(s): return sum(2 if ord(c) > 0x2E80 else 1 for c in s)

# ===== UI / ANSI =====
DUCK_ICON  = "🦆💨"
ICON_W     = wcswidth(DUCK_ICON)
TRACK_CHAR = "-"
BAR        = "|"
CLEAR, HOME = "\x1b[2J", "\x1b[H]".replace("]", "")  # -> "\x1b[H"

BANNER_ASCII = [
    r" __        __   _                            _          ____             _       ____                  _          ____                ",
    r" \ \      / /__| | ___ ___  _ __ ___   ___  | |_ ___   |  _ \ _   _  ___| | __  / ___|_ __ _   _ _ __ | |_ ___   |  _ \ __ _  ___ ___ ",
    r"  \ \ /\ / / _ \ |/ __/ _ \| '_ ` _ \ / _ \ | __/ _ \  | | | | | | |/ __| |/ / | |   | '__| | | | '_ \| __/ _ \  | |_) / _` |/ __/ _ \ ",
    r"   \ V  V /  __/ | (_| (_) | | | | | |  __/ | || (_) | | |_| | |_| | (__|   <  | |___| |  | |_| | |_) | || (_) | |  _ < (_| | (_|  __/ ",
    r"    \_/\_/ \___|_|\___\___/|_| |_| |_|\___|  \__\___/  |____/ \__,_|\___|_|\_\  \____|_|   \__, | .__/ \__\___/  |_| \_\__,_|\___\___| ",
    r"                                                                                           |___/|_|                                    ",
]

def print_banner(send):
    for line in BANNER_ASCII:
        send(line)
    send("")  # dòng trống sau banner

# ===== Helpers =====
def sha1_hex(x: int) -> str: return hashlib.sha1(str(x).encode()).hexdigest()
def ticket_of(seed: int) -> int: return (seed * 31337 + 1337) & 0xFFFF
def seed_for_round(secret: int, r: int) -> int: return (secret ^ ((r * ROUND_CONST) % MOD)) % MOD
def derive_int(*parts, bits=64):
    h = hashlib.sha1()
    for p in parts: h.update(str(p).encode()); h.update(b"|")
    return int.from_bytes(h.digest(), "big") & ((1<<bits)-1)

# ===== Game =====
TILE_NORMAL, TILE_BOOST, TILE_MUD, TILE_OIL = ".", "B", "M", "O"

class FancyTrack:
    def __init__(self, seed, lane, length):
        rng = random.Random(derive_int("track", seed, lane, length, bits=64))
        self.tiles = []
        for _ in range(length):
            r = rng.random()
            self.tiles.append(TILE_BOOST if r<0.06 else TILE_MUD if r<0.11 else TILE_OIL if r<0.16 else TILE_NORMAL)
    def at(self, x, length): return self.tiles[x] if 0 <= x < length else TILE_NORMAL

class DuckEngine:
    def __init__(self, seed, n, length=60):
        self.rng = random.Random(seed)
        self.n, self.length = n, length
        self.x   = [0]*n
        self.cd  = [0]*n
        self.trk = [FancyTrack(seed, i, length) for i in range(n)]
        self.wind_bias = self.rng.random()*0.08
        self.wind_puff = self.rng.random()*0.05
        self.finish_eps = [ (derive_int("finish_eps", seed, i, length, bits=64)/float(1<<64))*1e-6 + i*1e-9 for i in range(n) ]

    def step_once(self):
        prev = self.x[:]
        for i in range(self.n):
            prog = self.x[i]/max(1,self.length)
            step = self.rng.choice([0,1,1,1,2] if prog<0.7 else [0,1,1,1,1,2])
            if self.rng.random() < self.wind_bias: step += 1
            if self.rng.random() < self.wind_puff: step += 1
            if any(px - prev[i] in (1,2) for j,px in enumerate(prev) if j!=i): step += 1
            tentative = min(self.length, self.x[i]+step)
            tile = self.trk[i].at(tentative, self.length)
            slip_p = 0.05 + (0.10 if tile==TILE_OIL else 0.0)
            if tile==TILE_BOOST: step += 1
            elif tile==TILE_MUD: step = max(0, step-1)
            if self.rng.random() < slip_p:
                self.x[i] = max(0, self.x[i]-1)
                if self.cd[i]>0: self.cd[i]-=1
                continue
            if self.cd[i]<=0 and self.rng.random()<0.08:
                step += 2
                self.cd[i] = self.rng.randint(10,16)
            self.x[i] = min(self.length, self.x[i]+step)
            if self.cd[i]>0: self.cd[i]-=1

    def winner_1based_eps(self):
        best_i, best_s = 0, -1e99
        for i in range(self.n):
            s = self.x[i] - (self.length + self.finish_eps[i])
            if s > best_s: best_s, best_i = s, i
        return [best_i+1]

# ===== Net I/O =====
def sendln(send, s): 
    try: send((s+"\n").encode())
    except BrokenPipeError: pass

def recvline(recv, maxlen=200, timeout=45.0):
    end, buf = time.time()+timeout, b""
    while time.time() < end and len(buf) < maxlen:
        try: chunk = recv(1)
        except Exception: continue
        if not chunk: break
        c = chunk[:1]
        if c==b"\n": break
        if c!=b"\r": buf += c
    return buf.decode(errors="ignore").strip()

# ===== Render =====
def render_lane(i, pos, length, bet_idx=None, status="", tile_tag=""):
    star  = "*" if (bet_idx is not None and bet_idx==i) else " "
    prefix= f"  {star} "
    p = min(length, pos)
    left  = TRACK_CHAR * max(0, length - p - ICON_W)
    right = TRACK_CHAR * p
    extra = (f" [{status}]" if status else "") + (f" [{tile_tag}]" if tile_tag in (TILE_BOOST,TILE_MUD,TILE_OIL) else "")
    return prefix + f"{BAR}{left}{DUCK_ICON}{right}{BAR}" + extra

def render_frame(send, eng, length, bet_idx, t0, r_idx, rounds, commit, ticket):
    send(CLEAR+HOME)
    send(f"🦆 Duck Race (CTF, → trái) — round {r_idx}/{rounds} — t: {time.time()-t0:0.1f}s")
    send(f"COMMIT: {commit}")
    send(f"TICKET: {ticket}")
    send(f"Đặt cược: lane #{bet_idx+1}" if bet_idx is not None else "Không đặt cược.")
    send("")
    header_prefix = "    "
    send("⟵ ĐÍCH")
    send(header_prefix + BAR + TRACK_CHAR*length + BAR)
    for i in range(eng.n):
        tile = eng.trk[i].at(min(eng.x[i], length-1), eng.length)
        send(render_lane(i, eng.x[i], length, bet_idx=bet_idx, status="", tile_tag=tile))
    send(header_prefix + BAR + TRACK_CHAR*length + BAR)
    send("\nNOTE: Vịt có thể 'sprint' hoặc 'slip' bất ngờ.")

# ===== Server =====
class Cfg: 
    def __init__(self, host, port, rounds, ducks_start, inc, track_len, tick):
        self.host, self.port, self.rounds, self.ducks_start, self.inc, self.track_len, self.tick = host, port, rounds, ducks_start, inc, track_len, tick

class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(3.0)
        W, R = self.request.sendall, self.request.recv
        send = lambda s: sendln(W, s)
        recv = lambda   : recvline(R)

        cfg = self.server.cfg
        secret = random.getrandbits(BITS)

        print_banner(send)
        send("Bạn phải chọn lane thắng (1..N) trước khi đua")

        for r in range(1, cfg.rounds+1):
            n     = cfg.ducks_start + (r-1 if cfg.inc else 0)
            seed  = seed_for_round(secret, r)
            commit= sha1_hex(seed)
            ticket= ticket_of(seed)

            send(f"Round {r}/{cfg.rounds}")
            send(f"COMMIT: {commit}")
            send(f"TICKET: {ticket}")
            send(f"Hãy nhập chỉ số vịt thắng (1..{n}) trước khi đua: ")
            s = recv()
            if not s.isdigit() or not (1 <= int(s) <= n): send("Input không hợp lệ. Bye."); return
            bet_idx = int(s)-1

            eng, t0 = DuckEngine(seed, n, cfg.track_len), time.time()
            for _ in range(6):
                render_frame(send, eng, cfg.track_len, bet_idx, t0, r, cfg.rounds, commit, ticket); time.sleep(cfg.tick)
            while max(eng.x) < eng.length:
                eng.step_once()
                render_frame(send, eng, cfg.track_len, bet_idx, t0, r, cfg.rounds, commit, ticket); time.sleep(cfg.tick)

            winners = eng.winner_1based_eps()
            send("\nKẾT QUẢ:"); send(f"- Quán quân: lane #{winners[0]}")
            send(f"REVEAL seed = {seed}"); send(f"SHA1(seed) = {sha1_hex(seed)}")
            if (bet_idx+1) not in winners: send("Bạn đoán sai. GG!"); return
            if r < cfg.rounds: send("Đúng! Vào round tiếp theo...\n"); time.sleep(0.6)

        send(f"Tuyệt vời! Bạn đã đoán đúng tất cả {cfg.rounds} round."); send(f"FLAG: {FLAG}")

class Server(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True; daemon_threads = True

def main():
    p = argparse.ArgumentParser(description="Duck Crypto Race (gọn, Right→Left, single-winner)")
    p.add_argument("--host", default=env_str("HOST","0.0.0.0"))
    p.add_argument("--port", type=int, default=env_int("PORT",31337))
    p.add_argument("--rounds", type=int, default=env_int("ROUNDS",30))
    p.add_argument("--ducks-start", type=int, default=env_int("DUCKS_START",3))
    p.add_argument("--no-inc", dest="inc", action="store_false"); p.set_defaults(inc=(env_str("INC","1")!="0"))
    p.add_argument("--track-len", type=int, default=env_int("TRACK_LEN",60))
    p.add_argument("--tick", type=float, default=env_flt("TICK",0.08))
    a = p.parse_args()
    cfg = Cfg(a.host, a.port, a.rounds, a.ducks_start, a.inc, a.track_len, a.tick)
    with Server((cfg.host, cfg.port), Handler) as s:
        s.cfg = cfg
        sys.stderr.write(f"[+] Listening on {cfg.host}:{cfg.port} (rounds={cfg.rounds}, tick={cfg.tick}s)\n")
        try: s.serve_forever()
        except KeyboardInterrupt: sys.stderr.write("\n[!] Shutting down\n")

if __name__ == "__main__": main()

#!/usr/bin/env python3
from pwn import remote
import re, hmac, hashlib, random

HOST, PORT = "34.162.20.138", 5000

# -------- MT19937 untemper (đảo tempering) --------
def unshift_right_xor(y, shift):
    x = y
    for _ in range(5):
        x = y ^ (x >> shift)
    return x & 0xffffffff

def unshift_left_xor_mask(y, shift, mask):
    x = y
    for _ in range(5):
        x = y ^ ((x << shift) & mask)
    return x & 0xffffffff

def untemper(y):
    y = unshift_right_xor(y, 18)
    y = unshift_left_xor_mask(y, 15, 0xefc60000)
    y = unshift_left_xor_mask(y, 7,  0x9d2c5680)
    y = unshift_right_xor(y, 11)
    return y & 0xffffffff

class MTRecover:
    def __init__(self):
        self.state = []
        self.rng = None

    def submit(self, out32):
        self.state.append(untemper(out32))

    def ready(self):
        return len(self.state) >= 624

    def _init_rng(self):
        if self.rng is None:
            self.rng = random.Random()
            # python random state format: (3, (624_state_words + [index]), None)
            self.rng.setstate((3, tuple(self.state[:624] + [624]), None))

    def predict_getrandbits32(self):
        self._init_rng()
        return self.rng.getrandbits(32)

# -------- reproduce server roll logic --------
def compute_roll(server_seed: int, client_seed: str, nonce: int) -> int:
    msg = f"{client_seed}-{nonce}".encode()
    sig = hmac.new(str(server_seed).encode(), msg, hashlib.sha256).hexdigest()
    idx = 0
    lucky = int(sig[idx*5:idx*5+5], 16)
    while lucky >= 1_000_000:
        idx += 1
        lucky = int(sig[idx*5:idx*5+5], 16)  # slice can be 4 hex at end; still OK
    return round(((lucky % 10000) * 1e-2))

# -------- IO helpers --------
re_bal = re.compile(rb"Balance:\s*([0-9]+(?:\.[0-9]+)?)")
re_seed = re.compile(rb"Server-Seed:\s*([0-9]+)")
re_nonce = re.compile(rb"Nonce:\s*([0-9]+)")

def recv_menu(io):
    data = io.recvuntil(b"> ")
    m = re_bal.search(data)
    if not m:
        raise RuntimeError("Cannot parse balance")
    return float(m.group(1)), data

def play_one(io, wager, games, greed, confirm="Y"):
    io.sendline(b"b")
    io.recvuntil(b"Wager per game")
    io.sendline(str(wager).encode())
    io.recvuntil(b"Number of games")
    io.sendline(str(games).encode())
    io.recvuntil(b"Enter your number")
    io.sendline(str(greed).encode())
    io.recvuntil(b"(Y/N)")
    io.sendline(confirm.encode())

    # read until we see Server-Seed and Final Balance then back to menu
    out = io.recvuntil(b"Final Balance:")
    out += io.recvline()
    return out

def main():
    io = remote(HOST, PORT)
    client_seed = "1337awesome"  # mặc định; bạn cũng có thể set riêng

    bal, _ = recv_menu(io)

    # 1) collect 624 server seeds cheaply
    cracker = MTRecover()
    nonce = 0

    for i in range(624):
        min_wager = bal / 800.0 + 1e-4
        out = play_one(io, wager=min_wager, games=1, greed=98)

        mseed = re_seed.search(out)
        mnonce = re_nonce.search(out)
        if not (mseed and mnonce):
            raise RuntimeError("Cannot parse server-seed/nonce")

        server_seed = int(mseed.group(1))
        nonce = int(mnonce.group(1)) + 1  # server increments after printing
        cracker.submit(server_seed)

        bal, _ = recv_menu(io)

    assert cracker.ready()

    # 2) now predict future rolls; wait for a roll <= 2 then all-in
    while bal < 10000:
        next_seed = cracker.predict_getrandbits32()
        roll = compute_roll(next_seed, client_seed, nonce)

        if roll <= 2:
            wager = bal
            greed = 2
        elif roll <= 98:
            wager = bal / 10  # tuỳ bạn; an toàn hơn all-in
            greed = max(2, roll)
        else:
            # burn bad nonce (99/100)
            wager = bal / 800.0 + 1e-4
            greed = 98

        out = play_one(io, wager=wager, games=1, greed=greed)
        nonce += 1
        bal, _ = recv_menu(io)

    # 3) buy flag
    io.sendline(b"a")
    io.recvuntil(b"> ")
    io.sendline(b"a")
    print(io.recvuntil(b"}").decode(errors="ignore"))

if __name__ == "__main__":
    main()

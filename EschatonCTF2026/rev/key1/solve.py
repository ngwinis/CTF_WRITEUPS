#!/usr/bin/env python3
import socket
import re

HOST = "node-5.mcsc.space"
PORT = 34188

def key_for(username: str) -> str:
    # djb2-like: h = h*33 + c (mod 2^32), seed 0x7a2f
    eax = 0x7a2f
    for ch in username.encode():
        eax = (eax + ((eax << 5) & 0xffffffff)) & 0xffffffff  # eax*33
        eax = (eax + ch) & 0xffffffff

    edx = (eax * 8) & 0xffffffff
    esi = eax & 0xffffffff

    # shr ax, 5 (16-bit only)
    ax = ((eax & 0xffff) >> 5) & 0xffff
    eax = (eax & 0xffff0000) | ax

    eax = (eax ^ edx) & 0xffffffff

    # xor si, 0x9c3e (16-bit only)
    si = (esi & 0xffff) ^ 0x9c3e
    esi = (esi & 0xffff0000) | (si & 0xffff)

    # xor ax, 0xb7a1 (16-bit only)
    ax = (eax & 0xffff) ^ 0xb7a1
    eax = (eax & 0xffff0000) | (ax & 0xffff)

    edx = (esi + eax) & 0xffffffff
    ecx = (eax ^ edx) & 0xffffffff

    # xor dx, 0xe4d2 ; xor cx, 0x78ec (16-bit only)
    dx = (edx & 0xffff) ^ 0xe4d2
    edx = (edx & 0xffff0000) | (dx & 0xffff)

    cx = (ecx & 0xffff) ^ 0x78ec
    ecx = (ecx & 0xffff0000) | (cx & 0xffff)

    w0 = esi & 0xffff
    w1 = eax & 0xffff
    w2 = edx & 0xffff
    w3 = ecx & 0xffff
    return f"{w0:04x}-{w1:04x}-{w2:04x}-{w3:04x}"

def main():
    s = socket.create_connection((HOST, PORT))
    buf = b""
    sent_for = set()

    # match "Username: <name>\n" (name can include underscores)
    user_re = re.compile(rb"Username:\s*([^\r\n]+)\r?\n")

    while True:
        data = s.recv(4096)
        if not data:
            break

        # show server output live
        try:
            print(data.decode(errors="replace"), end="")
        except Exception:
            pass

        buf += data

        # process any usernames that appeared
        while True:
            m = user_re.search(buf)
            if not m:
                break

            username = m.group(1).decode(errors="replace").strip()

            # only send when the prompt "Enter key:" appears AFTER this match
            after = buf[m.end():]
            if b"Enter key" not in after:
                # wait for more data
                break

            if username not in sent_for:
                k = key_for(username)
                s.sendall(k.encode() + b"\n")
                sent_for.add(username)

            # trim buffer up to after "Enter key:" to avoid reprocessing
            idx = buf.find(b"Enter key", m.end())
            if idx != -1:
                buf = buf[idx + len(b"Enter key"):]
            else:
                buf = after

    s.close()

if __name__ == "__main__":
    main()

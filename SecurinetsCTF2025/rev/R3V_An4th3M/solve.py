# chạy trên máy bạn: Python 3
import base64, zlib, itertools

blob = open("R3V_An4th3M.EXE","rb").read()

def get_section(blob, name=b"::XTN::"):
    import struct
    if blob[:2]!=b"MZ": raise SystemExit("Not PE")
    e_lfanew = int.from_bytes(blob[0x3C:0x40],"little")
    if blob[e_lfanew:e_lfanew+4]!=b"PE\x00\x00": raise SystemExit("No PE")
    num = int.from_bytes(blob[e_lfanew+6:e_lfanew+8], "little")
    opt = e_lfanew+24
    size_opt = int.from_bytes(blob[e_lfanew+20:e_lfanew+22],"little")
    sect = opt+size_opt
    for i in range(num):
        off = sect + i*40
        nm  = blob[off:off+8].split(b"\x00",1)[0]
        raw = int.from_bytes(blob[off+20:off+24],"little")
        rsz = int.from_bytes(blob[off+16:off+20],"little")
        if nm == name:
            return blob[raw:raw+rsz]
    return None

xtn = get_section(blob)
cands = [b"Ad3M", b"XTN", b"SecurinetsQUALS", b"Prot3cted bY Ad3M XTN"]

def rc4(key, data):
    S=list(range(256)); j=0
    for i in range(256):
        j=(j+S[i]+key[i%len(key)])&0xff
        S[i],S[j]=S[j],S[i]
    i=j=0; out=bytearray()
    for b in data:
        i=(i+1)&0xff; j=(j+S[i])&0xff
        S[i],S[j]=S[j],S[i]
        K=S[(S[i]+S[j])&0xff]
        out.append(b^K)
    return bytes(out)

def search(buf):
    return b"Securinets{" in buf

# thử vài biến đổi
def try_all(b):
    # XOR đơn byte
    for v in range(256):
        t = bytes(x^v for x in b)
        if search(t): return ("xor1", v, t)
    # rolling XOR theo index
    for d in range(1,16):
        t = bytes(b[i]^((i*d)&0xff) for i in range(len(b)))
        if search(t): return ("xor_idx", d, t)
    # ADD rolling
    for d in range(1,16):
        t = bytes((b[i]+(i*d))&0xff for i in range(len(b)))
        if search(t): return ("add_idx", d, t)
    # RC4 với key gợi ý
    for k in cands:
        t = rc4(k, b)
        if search(t): return ("rc4", k, t)
    return None

print(try_all(xtn))

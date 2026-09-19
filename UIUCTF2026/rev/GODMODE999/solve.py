#!/usr/bin/env python3
# GODMODE//999 solve script
# Usage: python3 godmode_solve.py ranked.img
from pathlib import Path
import sys, struct, hashlib, glob

try:
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
except Exception:
    ChaCha20Poly1305 = None

PLAYER_CODE = b"r0llb4ck_th3_un1v3rs3_4nd_qu3u3_f0r_LV999!!!n0w!"

def u16(b,o): return struct.unpack_from('<H', b, o)[0]
def u32(b,o): return struct.unpack_from('<I', b, o)[0]
def p32(x): return struct.pack('<I', x & 0xffffffff)
def rol(x,r):
    r &= 31
    return (((x << r) | (x >> (32-r))) & 0xffffffff) if r else (x & 0xffffffff)

def cksum(data, zero_off):
    b = bytearray(data)
    b[zero_off:zero_off+4] = b'\0\0\0\0'
    h = 0x811c9dc5
    for x in b:
        h ^= x
        h = (h * 0x01000193) & 0xffffffff
        h ^= h >> 13
        h &= 0xffffffff
    return h

class Entry:
    def __init__(self):
        self.name = bytearray(0x30); self.block = 0; self.length = 0; self.id = 0; self.valid = 0
    def copy(self):
        e = Entry(); e.name = bytearray(self.name); e.block = self.block; e.length = self.length; e.id = self.id; e.valid = self.valid
        return e
    def path(self): return bytes(self.name).split(b'\0')[0].decode('ascii', 'ignore')

class StateFS:
    def __init__(self): self.entries=[]; self.lastseq=0
    def copy(self):
        s = StateFS(); s.entries=[e.copy() for e in self.entries]; s.lastseq=self.lastseq
        return s

def recover_rankedfs(img):
    # superblock is at block 1 (0x1000)
    sb = img[0x1000:0x1000+0x3c]
    assert sb[:4] == b'RNK9' and u32(sb,0x18) == cksum(sb,0x18)
    journal_start, journal_count = u32(sb,0xc), u32(sb,0x10)

    def rec(i):
        d = img[(journal_start*4096)+(i*128):(journal_start*4096)+((i+1)*128)]
        assert d[:4] == b'JRNL' and u32(d,0x1c) == cksum(d,0x1c)
        return d

    def apply(st, d):
        op, rid = d[4], u32(d,0x10)
        if op == 1:          # create
            e = next((x for x in st.entries if x.id == rid), None)
            if e is None:
                e = Entry(); e.id = rid; st.entries.append(e)
            e.name = bytearray(d[0x20:0x50]); e.valid = 1
        elif op == 2:        # set block/length
            for e in st.entries:
                if e.id == rid:
                    e.block = u32(d,0x14); e.length = u32(d,0x18); break
        elif op == 3:        # rename
            for e in st.entries:
                if e.id == rid:
                    e.name = bytearray(d[0x50:0x80]); break
        elif op == 4:        # delete
            for e in st.entries:
                if e.id == rid:
                    e.valid = 0; break

    cur, snap, snap_tx, committed = StateFS(), StateFS(), None, StateFS()
    for i in range(journal_count):
        d, op, tx = rec(i), rec(i)[4], u32(rec(i),0x0c)
        if op == 5:          # begin speculative transaction
            snap, snap_tx = cur.copy(), tx
        elif op == 6:        # rollback
            if tx == snap_tx: cur = snap.copy()
        elif op == 7:        # commit
            committed = cur.copy(); committed.lastseq = u32(d,0x08)
        else:
            apply(cur, d)

    h = hashlib.blake2s(); h.update(b'RANKEDFS-COMMITTED'); h.update(p32(committed.lastseq))
    for e in committed.entries:
        if e.valid:
            h.update(p32(e.id)); h.update(p32(e.block)); h.update(p32(e.length)); h.update(bytes(e.name))
    fs_key = h.digest()

    def decrypt(e):
        out = bytearray()
        for pos in range(e.length):
            block = e.block + (pos >> 12)
            page_off = pos & 0xfff
            idx = pos >> 5
            ks = hashlib.blake2s(fs_key + p32(e.id) + p32(idx) + b'RANKEDFS-BLOCK').digest()
            out.append(img[block*4096 + page_off] ^ ks[pos & 31])
        return bytes(out)

    return {e.path(): decrypt(e) for e in committed.entries if e.valid}, committed.lastseq

class Node:
    def __init__(self, raw):
        self.raw=raw; self.id=u16(raw,0); self.prio=u16(raw,2); self.opidx=raw[4]; self.tie=raw[5]
        self.dst=u16(raw,8); self.src=u16(raw,10)
        self.a0=u32(raw,0x10); self.a1=u32(raw,0x14); self.a2=u32(raw,0x18)
        assert u32(raw,0x1c) == cksum(raw,0x1c)

class Raid:
    def __init__(self, data):
        self.data=data; assert data[:8] == b'RAID//9\0' and u32(data,0x2c) == cksum(data[:0x100],0x2c)
        self.stage=data[0xc]; self.nodes_n=u16(data,0x10); self.edges_n=u16(data,0x12)
        self.lanes_n=u16(data,0x14); self.off=u16(data,0x16); self.lane_bytes=u16(data,0x18)
        no,eo,lo = u32(data,0x20), u32(data,0x24), u32(data,0x28)
        self.nodes=[Node(data[no+i*32:no+(i+1)*32]) for i in range(self.nodes_n)]
        self.edges=[(u16(data,eo+i*8), u16(data,eo+i*8+2)) for i in range(self.edges_n)]
        self.enc_targets=data[lo:lo+self.lanes_n*4]
    def order(self):
        indeg=[0]*self.nodes_n
        for a,b in self.edges: indeg[b] += 1
        used=[False]*self.nodes_n; out=[]
        for _ in range(self.nodes_n):
            cand=[n for n in self.nodes if not used[n.id] and indeg[n.id] == 0]
            n=min(cand, key=lambda x:(x.prio,x.tie,x.id))
            out.append(n); used[n.id]=True
            for a,b in self.edges:
                if a == n.id: indeg[b] -= 1
        return out

def derive(label, lastseq, st, stage, nonce):
    h=hashlib.blake2s(); h.update(label); h.update(p32(lastseq)); h.update(bytes([stage]))
    if stage: h.update(st[:stage*16])
    h.update(nonce)
    return h.digest()

def map_key(r,lastseq,st):
    if r.stage == 0: return r.data[0x30:0x40]
    k = derive(b'RAID9-MAP', lastseq, st, r.stage, r.data[0x40:0x50])
    return bytes(r.data[0x30+i] ^ k[i] for i in range(16))

def targets(r,lastseq,st):
    k = derive(b'RAID9-TARGET', lastseq, st, r.stage, r.data[0x68:0x78])
    raw=bytearray()
    for i in range((len(r.enc_targets)+31)//32):
        ks=hashlib.blake2s(k+p32(i)).digest()
        c=r.enc_targets[i*32:(i+1)*32]
        raw.extend(c[j]^ks[j] for j in range(len(c)))
    return [u32(raw,4*i) for i in range(len(raw)//4)]

def checkpoint_hash(lanes,a0):
    x=(a0 ^ 0x9e3779b9) & 0xffffffff; y=0x7f4a7c15
    for i,v in enumerate(lanes):
        t=(y ^ v); t=(t+x)&0xffffffff; y=(y+0x7f4a7c15)&0xffffffff
        x=rol(t,(i%19)+7); x=(x*0x85ebca6b)&0xffffffff; x ^= x>>16
    return x & 0xffffffff

def run_raid(r,lastseq,st,code):
    lanes=[0]*r.lanes_n; snap=[0]*r.lanes_n; checkpoint=False; mmr=u32(st,0x50); cp_mmr=mmr; commit=False
    mk=map_key(r,lastseq,st)
    for n in r.order():
        op=mk[n.opidx]; src=n.src%r.lanes_n; dst=n.dst%r.lanes_n
        if op == 0: lanes[dst]=u32(code,r.off+n.a0)
        elif op == 1: lanes[dst]=n.a0
        elif op == 2: lanes[dst]=(lanes[dst]+n.a0+rol(lanes[src],n.a1))&0xffffffff
        elif op == 3: lanes[dst]=(lanes[dst]^rol((lanes[src]+n.a0)&0xffffffff,n.a1))&0xffffffff
        elif op == 4: lanes[dst]=(((n.a0|1)*lanes[dst])+n.a1)&0xffffffff
        elif op == 5:
            x=(lanes[dst]^n.a1)&0xffffffff; x^=x>>13; x&=0xffffffff; x=((n.a0|1)*x)&0xffffffff; x^=(x<<7)&0xffffffff
            lanes[dst]=(x+n.a2)&0xffffffff
        elif op == 6:
            a,b=lanes[src],lanes[dst]
            t=(rol(a^n.a0,n.a2)+b)&0xffffffff; lanes[dst]=t
            lanes[src]=(rol((t+n.a1)&0xffffffff,(n.a2>>8)&31)^a)&0xffffffff
        elif op in (7,12): lanes[src],lanes[dst]=lanes[dst],lanes[src]
        elif op == 8: snap=lanes.copy(); checkpoint=True; cp_mmr=mmr
        elif op == 9:
            if not checkpoint: raise RuntimeError('bad checkpoint')
            if checkpoint_hash(lanes,n.a0) == n.a1: snap=lanes.copy(); cp_mmr=mmr
            else: lanes=snap.copy(); mmr=cp_mmr
        elif op == 10: mmr=(rol(lanes[src]^mmr,n.a1)^n.a0)&0xffffffff
        elif op == 11: commit=True
        else: raise RuntimeError('unknown opcode')
    assert commit and lanes == targets(r,lastseq,st)

    h=hashlib.blake2s(); h.update(b'RAID9-DROP'); h.update(bytes([r.stage])); h.update(b''.join(p32(x) for x in lanes)); h.update(p32(mmr)); h.update(code[r.off:r.off+r.lane_bytes])
    digest=h.digest(); new=bytearray(st)
    if r.stage <= 2:
        seg=bytes(digest[i] ^ r.data[0x50+i] for i in range(16))
        assert hashlib.blake2s(seg+r.data[0x40:0x50]).digest()[:8] == r.data[0x60:0x68]
        new[r.stage*16:r.stage*16+16]=seg
    h=hashlib.blake2s(); h.update(new[0x30:0x50]); h.update(r.data[0x40:0x50]); h.update(b''.join(p32(x) for x in lanes)); h.update(p32(mmr))
    new[0x30:0x50]=h.digest(); new[0x50:0x54]=p32(mmr)
    return new

def main():
    if len(sys.argv) > 1: img_path = Path(sys.argv[1])
    else:
        hits = glob.glob('ranked*.img') or glob.glob('/mnt/data/ranked*.img')
        if not hits: raise SystemExit('usage: python3 godmode_solve.py ranked.img')
        img_path = Path(hits[0])
    img = img_path.read_bytes()
    files,lastseq = recover_rankedfs(img)
    print('[+] files:', ', '.join(files))

    st=bytearray(0x54); st[0x50:0x54]=p32(995)
    for name in ['/replays/tutorial.raid','/replays/placement.raid','/replays/promotion.raid','/replays/godmode.raid']:
        st=run_raid(Raid(files[name]), lastseq, st, PLAYER_CODE)
        print('[+] ok', name, 'MMR =', u32(st,0x50))

    ach=files['/cache/achievement.bin']
    key=hashlib.blake2s(PLAYER_CODE + st[0x30:0x50] + st[0x50:0x54] + st[:0x30] + ach[0x0c:0x10]).digest()
    nonce=ach[0x14:0x20]; tag=ach[0x20:0x30]; n=u32(ach,0x10); ct=ach[0x40:0x40+n]
    if ChaCha20Poly1305 is None:
        raise SystemExit('install cryptography: python3 -m pip install cryptography')
    flag = ChaCha20Poly1305(key).decrypt(nonce, ct+tag, b'').decode()
    print('[+] PLAYER_CODE =', PLAYER_CODE.decode())
    print('[+] FLAG =', flag)

if __name__ == '__main__': main()

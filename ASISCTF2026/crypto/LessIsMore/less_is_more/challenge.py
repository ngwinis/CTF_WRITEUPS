#!/usr/bin/env python3

import json
import os
import struct
import hashlib

try:
	from Crypto.Cipher import AES
except ImportError:
	from cryptography.hazmat.primitives.ciphers.aead import AESGCM

	class _GCM:
		def __init__(self, key, nonce):
			self.key = key
			self.nonce = nonce

		def encrypt_and_digest(self, data):
			out = AESGCM(self.key).encrypt(self.nonce, data, None)
			return out[:-16], out[-16:]

	class AES:
		MODE_GCM = object()

		@staticmethod
		def new(key, mode, nonce):
			if mode is not AES.MODE_GCM:
				raise ValueError("unsupported mode")
			return _GCM(key, nonce)

try:
	from Crypto.Hash import SHA256, SHA3_256, SHAKE256
except ImportError:
	class _Hash:
		def __init__(self, h):
			self.h = h

		def update(self, data):
			self.h.update(data)

		def digest(self):
			return self.h.digest()

	class _Shake:
		def __init__(self, data=b''):
			self.h = hashlib.shake_256()
			self.h.update(data)
			self.pos = 0

		def update(self, data):
			self.h.update(data)

		def read(self, n):
			out = self.h.digest(self.pos + n)[self.pos:self.pos + n]
			self.pos += n
			return out

	class SHA256:
		@staticmethod
		def new(data=b''):
			return _Hash(hashlib.sha256(data))

	class SHA3_256:
		@staticmethod
		def new(data=b''):
			return _Hash(hashlib.sha3_256(data))

	class SHAKE256:
		@staticmethod
		def new(data=b''):
			return _Shake(data)

try:
	from flag import flag
except ImportError:
	flag = b'ASIS{iZ_7Hi5__dUmMy__flag!!?}'

q, n, k = 127, 548, 274
t, w, s = 137, 79, 12
lam, lvs = 16, 256

def ginv(a):
	return pow(a, -1, q)


def st_of(*ps):
	h = SHAKE256.new()
	for p in ps:
		h.update(p)
	return h

def spm(st, nn):
	p = list(range(nn))
	for j in range(nn - 1, 0, -1):
		md = j + 1
		lm = 65536 - (65536 % md)
		while True:
			x = int.from_bytes(st.read(2), 'little')
			if x < lm:
				break
		x %= md
		p[j], p[x] = p[x], p[j]
	d = []
	while len(d) < nn:
		for byte in st.read(64):
			if byte < 126:
				d.append(byte + 1)
				if len(d) == nn:
					break
	return p, d

def mua(A, M):
	p, d = M
	return [[(row[p[j]] * d[j]) % q for j in range(len(p))] for row in A]

def miv(M):
	p, d = M
	nn = len(p)
	pi, di = [0] * nn, [0] * nn
	for j in range(nn):
		pi[p[j]] = j
		di[p[j]] = ginv(d[j])
	return pi, di

def rxt(A):
	M = [row[:] for row in A]
	pivs = []
	r = 0
	for c in range(n):
		if r == k:
			break
		pr = -1
		for r2 in range(r, k):
			if M[r2][c]:
				pr = r2
				break
		if pr < 0:
			continue
		if pr != r:
			M[r], M[pr] = M[pr], M[r]
		iv = ginv(M[r][c])
		M[r] = [(x * iv) % q for x in M[r]]
		Mr = M[r]
		for r2 in range(k):
			if r2 != r and M[r2][c]:
				f = M[r2][c]
				M[r2] = [(a - f * b) % q for a, b in zip(M[r2], Mr)]
		pivs.append(c)
		r += 1
	if r != k:
		raise ValueError('rank deficient input')
	ps = set(pivs)
	return M, pivs + [c for c in range(n) if c not in ps]

def sch(cd):
	st = st_of(cd)
	vals = []
	while len(vals) < w:
		for byte in st.read(64):
			if byte < 252:
				vals.append(byte % (s - 1) + 1)
				if len(vals) == w:
					break
	b = vals + [0] * (t - w)
	for j in range(t - 1, 0, -1):
		md = j + 1
		lm = 65536 - (65536 % md)
		while True:
			x = int.from_bytes(st.read(2), 'little')
			if x < lm:
				break
		x %= md
		b[j], b[x] = b[x], b[j]
	return b

def kid(sd):
	return (SHA256.new(b'L' + sd).digest()[:lam],
			SHA256.new(b'R' + sd).digest()[:lam])

def srg(v):
	bits = []
	u = v
	while u > 1:
		bits.append(u & 1)
		u //= 2
	lo, hi = 0, lvs
	for b in reversed(bits):
		mid = (lo + hi) // 2
		if b:
			lo = mid
		else:
			hi = mid
	return lo, hi

def lvs_of(rt):
	seeds = {1: rt}
	out = [None] * lvs
	stack = [1]
	while stack:
		v = stack.pop()
		sd = seeds[v]
		if v >= lvs:
			out[v - lvs] = sd
			continue
		ls, rs = kid(sd)
		seeds[2 * v] = ls
		seeds[2 * v + 1] = rs
		stack.append(2 * v)
		stack.append(2 * v + 1)
	return out[:t]

def nds_of(rt):
	seeds = {1: rt}
	stack = [1]
	while stack:
		v = stack.pop()
		if v >= lvs:
			continue
		ls, rs = kid(seeds[v])
		seeds[2 * v] = ls
		seeds[2 * v + 1] = rs
		stack.append(2 * v)
		stack.append(2 * v + 1)
	return seeds

def cvr(P):
	Ps = set(P)
	if not Ps:
		raise ValueError('empty set')
	if all(i in Ps for i in range(t)):
		raise ValueError('everything covered')

	def ok(v):
		lo, hi = srg(v)
		real = [i for i in range(lo, hi) if i < t]
		return len(real) > 0 and all(i in Ps for i in real)

	out = []

	def walk(v):
		if ok(v):
			out.append(v)
			return
		if v < lvs:
			walk(2 * v)
			walk(2 * v + 1)

	walk(1)
	return out

def cmt_of(As, salt, msg):
	h = SHA3_256.new()
	for A in As:
		h.update(b''.join(bytes(row[k:]) for row in A))
	h.update(salt)
	h.update(msg)
	return h.digest()

def rsp_of(Qm, Pi, Qt):
	qq, qt = Qm[0], Qt[0]
	return sorted(qq[qt[Pi[j]]] for j in range(k))

def ckey(Qm):
	p, d = Qm
	nn = len(p)
	pi = [0] * nn
	for j in range(nn):
		pi[p[j]] = j
	D = [d[pi[i]] for i in range(nn)]
	iv = ginv(D[0])
	return p, [x * iv % q for x in D]

def vkey(cks):
	ser = b''.join(
		b''.join(struct.pack('<H', x) for x in p) + bytes(Dn)
		for p, Dn in cks)
	return SHA256.new(b'vault|' + ser).digest()[:16]

def keygen(st):
	M = []
	while len(M) < k:
		row = []
		while len(row) < k:
			for byte in st.read(64):
				if byte < 127:
					row.append(byte)
					if len(row) == k:
						break
		M.append(row)
	G0 = [[1 if i == j else 0 for j in range(k)] + M[i] for i in range(k)]
	sk, pk = [], []
	for _ in range(s - 1):
		while True:
			Qm = spm(st, n)
			try:
				R, pivs = rxt(mua(G0, miv(Qm)))
				assert pivs[:k] == list(range(k))
				sk.append(Qm)
				pk.append(R)
				break
			except (ValueError, AssertionError):
				continue
	return G0, sk, pk

def sgn(G0, sk, rt, salt, msg):
	lf = lvs_of(rt)
	Qts, As, Pis = [], [], []
	for i in range(t):
		st = st_of(lf[i], salt, struct.pack('<I', i))
		Qt = spm(st, n)
		A, Pi = rxt(mua(G0, Qt))
		Qts.append(Qt)
		As.append(A)
		Pis.append(Pi)
	cmt = cmt_of(As, salt, msg)
	b = sch(cmt)
	mk = [0] * t
	for i in range(t):
		mk[i] = 1 if b[i] else 0
	P = [i for i in range(t) if mk[i] == 0]
	nodes = nds_of(rt)
	path = [[v, nodes[v].hex()] for v in cvr(P)]
	rsp = []
	for i in range(t):
		if b[i]:
			rsp.append(rsp_of(sk[b[i] - 1], Pis[i], Qts[i]))
	return {'cmt': cmt.hex(), 'salt': salt.hex(), 'msg': msg.hex(),
			'path': path, 'rsp': rsp}

def main():
	master = os.urandom(32)
	G0, sk, pk = keygen(st_of(b'keygen', master))
	st = st_of(b'transcripts', master)
	txs = []
	for _ in range(3):
		while True:
			rt, salt, msg = st.read(lam), st.read(2 * lam), st.read(12)
			try:
				txs.append(sgn(G0, sk, rt, salt, msg))
				break
			except ValueError:
				continue
	key = vkey([ckey(Qm) for Qm in sk])
	nonce = os.urandom(12)
	cip = AES.new(key, AES.MODE_GCM, nonce=nonce)
	ct, tag = cip.encrypt_and_digest(flag)
	out = json.dumps({
		'meta': {'q': q, 'n': n, 'k': k, 't': t, 'w': w, 's': s,
				 'lam': lam, 'lvs': lvs},
		'G0': [row[k:] for row in G0],
		'PK': [[row[k:] for row in P] for P in pk],
		'tx': txs,
		'vault': {'nonce': nonce.hex(), 'ct': ct.hex(), 'tag': tag.hex()},
	}, separators=(',', ':'))
	with open('output.txt', 'w') as f:
		f.write(out + '\n')
	print('output.txt written')

if __name__ == '__main__':
	main()
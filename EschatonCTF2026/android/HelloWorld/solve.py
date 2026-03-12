#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import io
import re
import sys
import zlib
import tarfile
import zipfile
import sqlite3
import binascii
from pathlib import Path

from Crypto.Cipher import AES
from Crypto.Hash import SHA1, SHA512
from Crypto.Protocol.KDF import PBKDF2

# --- Challenge-specific secrets (from reversing) ---
ADB_BACKUP_PASSWORD = "hello world"
SQLCIPHER_PASSPHRASE = "1s_th1s_th3_fl4g?"

# --- Helpers ---
def unpad_pkcs7(b: bytes) -> bytes:
    if not b:
        raise ValueError("empty")
    n = b[-1]
    if n < 1 or n > 16 or b[-n:] != bytes([n]) * n:
        raise ValueError("bad pkcs7")
    return b[:-n]

def read_uleb128(buf: bytes, off: int) -> tuple[int, int]:
    res = 0
    shift = 0
    while True:
        b = buf[off]
        off += 1
        res |= (b & 0x7F) << shift
        if (b & 0x80) == 0:
            break
        shift += 7
    return res, off

def parse_ab_header(ab: bytes):
    bio = io.BytesIO(ab)
    if bio.readline().rstrip() != b"ANDROID BACKUP":
        raise ValueError("Not an Android backup")
    version = int(bio.readline())
    compressed = int(bio.readline())
    enc = bio.readline().strip().decode()

    if enc == "none":
        return {"enc": "none", "compressed": compressed, "offset": bio.tell()}

    user_salt = binascii.unhexlify(bio.readline().strip())
    ck_salt = binascii.unhexlify(bio.readline().strip())
    rounds = int(bio.readline())
    user_iv = binascii.unhexlify(bio.readline().strip())
    mk_blob = binascii.unhexlify(bio.readline().strip())
    return {
        "enc": enc, "compressed": compressed, "offset": bio.tell(),
        "user_salt": user_salt, "ck_salt": ck_salt, "rounds": rounds,
        "user_iv": user_iv, "mk_blob": mk_blob,
    }

def android_secret_from_master_key(master_key: bytes) -> bytes:
    # Android backup checksum uses the same weird "char[]" conversion trick.
    chars = []
    for b in master_key:
        signed = b - 256 if b >= 128 else b
        cp = signed if signed >= 0 else (0xFF00 + b)
        chars.append(chr(cp))
    return "".join(chars).encode("utf-8")

def decrypt_android_backup(ab: bytes, password: str) -> bytes:
    hdr = parse_ab_header(ab)
    payload = ab[hdr["offset"]:]

    if hdr["enc"] == "none":
        plain = payload
        return zlib.decompress(plain) if hdr["compressed"] else plain

    if hdr["enc"] != "AES-256":
        raise ValueError(f"Unsupported enc: {hdr['enc']}")

    # 1) derive user key
    user_key = PBKDF2(password.encode(), hdr["user_salt"], dkLen=32, count=hdr["rounds"], hmac_hash_module=SHA1)

    # 2) decrypt master-key blob
    blob_plain = unpad_pkcs7(AES.new(user_key, AES.MODE_CBC, iv=hdr["user_iv"]).decrypt(hdr["mk_blob"]))

    # blob format: [ivLen][iv][mkLen][mk][ckLen][ck]
    p = 0
    iv_len = blob_plain[p]; p += 1
    master_iv = blob_plain[p:p+iv_len]; p += iv_len
    mk_len = blob_plain[p]; p += 1
    master_key = blob_plain[p:p+mk_len]; p += mk_len
    ck_len = blob_plain[p]; p += 1
    checksum = blob_plain[p:p+ck_len]

    # 3) verify checksum (android char[] conversion)
    secret = android_secret_from_master_key(master_key)
    want = PBKDF2(secret, hdr["ck_salt"], dkLen=len(checksum), count=hdr["rounds"], hmac_hash_module=SHA1)
    if want != checksum:
        raise ValueError("Android backup password OK, but master-key checksum mismatch")

    # 4) decrypt payload with master_key/master_iv
    plain = unpad_pkcs7(AES.new(master_key, AES.MODE_CBC, iv=master_iv).decrypt(payload))
    return zlib.decompress(plain) if hdr["compressed"] else plain

def parse_wal_frames(wal: bytes, page_size: int):
    # WAL header is 32 bytes (plaintext, even for SQLCipher WAL)
    if len(wal) < 32:
        return []
    off = 32
    frames = []
    while off + 24 + page_size <= len(wal):
        fh = wal[off:off+24]
        pgno = int.from_bytes(fh[0:4], "big")
        dbsize = int.from_bytes(fh[4:8], "big")  # commit marker if != 0
        page = wal[off+24:off+24+page_size]
        frames.append((pgno, dbsize, page))
        off += 24 + page_size
    return frames

def decrypt_sqlcipher_page(enc_page: bytes, pgno: int, key: bytes, page_size: int, reserve: int) -> bytes:
    # Layout: [ (possibly plaintext header for pgno==1's first 16 bytes = salt) | ciphertext ... ][IV(16)][HMAC(...)]
    iv = enc_page[page_size - reserve : page_size - reserve + 16]

    if pgno == 1:
        # First 16 bytes on disk are salt, not ciphertext; SQLCipher patches magic in memory.
        ct = enc_page[16 : page_size - reserve]
        pt = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)
        plain = b"SQLite format 3\x00" + pt
    else:
        ct = enc_page[0 : page_size - reserve]
        pt = AES.new(key, AES.MODE_CBC, iv=iv).decrypt(ct)
        plain = pt

    plain += b"\x00" * reserve
    if len(plain) != page_size:
        raise ValueError("bad page rebuild")
    return plain

def reconstruct_plain_sqlite(enc_db: bytes, enc_wal: bytes, passphrase: str) -> bytes:
    # We know (from the lib / defaults) this DB uses SQLCipher v4-ish defaults:
    # PBKDF2-HMAC-SHA512, kdf_iter=256000, HMAC-SHA512 => reserve = 16 + 64 = 80.
    page_size = 4096
    reserve = 80

    salt = enc_db[:16]
    key = PBKDF2(passphrase.encode("utf-8"), salt, dkLen=32, count=256000, hmac_hash_module=SHA512)

    # WAL tells us final db page count via commit frames
    frames = parse_wal_frames(enc_wal, page_size)
    if not frames:
        # fallback: just decrypt the single db page
        plain1 = decrypt_sqlcipher_page(enc_db[:page_size], 1, key, page_size, reserve)
        return plain1

    page_map = {}
    final_db_pages = 0
    for pgno, dbsize, page in frames:
        page_map[pgno] = page
        if dbsize != 0:
            final_db_pages = dbsize

    if final_db_pages == 0:
        final_db_pages = max(page_map.keys())

    out = bytearray()
    for pgno in range(1, final_db_pages + 1):
        enc_page = page_map.get(pgno)
        if enc_page is None:
            # if WAL doesn't have it, read from main db (if present)
            start = (pgno - 1) * page_size
            enc_page = enc_db[start:start+page_size]
            if len(enc_page) != page_size:
                raise ValueError(f"missing page {pgno}")
        out += decrypt_sqlcipher_page(enc_page, pgno, key, page_size, reserve)

    return bytes(out)

def main(path: str):
    ab = Path(path).read_bytes()
    tar_bytes = decrypt_android_backup(ab, ADB_BACKUP_PASSWORD)

    tf = tarfile.open(fileobj=io.BytesIO(tar_bytes), mode="r:*")
    enc_db = tf.extractfile("apps/com.mcsc.helloworld/db/.notinhere.db").read()
    enc_wal = tf.extractfile("apps/com.mcsc.helloworld/db/.notinhere.db-wal").read()

    plain_sqlite = reconstruct_plain_sqlite(enc_db, enc_wal, SQLCIPHER_PASSPHRASE)

    # query notes for anything flag-like
    tmp = io.BytesIO(plain_sqlite)
    # sqlite3 wants a filename; write to temp on disk
    tmp_path = Path("decrypted.sqlite")
    tmp_path.write_bytes(plain_sqlite)

    con = sqlite3.connect(str(tmp_path))
    rows = con.execute("SELECT id, title, content, deleted FROM notes ORDER BY id").fetchall()
    con.close()

    flag_re = re.compile(r"[A-Za-z0-9_]{2,}\{[^}]+\}")
    found = []
    for _id, title, content, deleted in rows:
        if content:
            m = flag_re.search(content)
            if m:
                found.append((m.group(0), _id, deleted, title))

    if not found:
        print("No flag-like string found.")
        return

    # Prefer deleted notes (forensics vibe)
    found.sort(key=lambda x: (x[2] == 0, x[1]))  # deleted==1 first, then id
    print(found[0][0])

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} helloworld.dat")
        sys.exit(1)
    main(sys.argv[1])

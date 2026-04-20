#!/usr/bin/env python3
from pwn import *
import random
import subprocess

MASK32 = 0xFFFFFFFF

def split_block(block):
    return ((block >> 32) & MASK32, block & MASK32)

def join_block(left, right):
    return ((left & MASK32) << 32) | (right & MASK32)

def rotl32(x, r):
    x &= MASK32
    return ((x << r) & MASK32) | (x >> (32 - r))

def rotr32(x, r):
    x &= MASK32
    return ((x >> r) | (x << (32 - r))) & MASK32

def sbox_layer(x, sboxes):
    y = 0
    for i in range(8):
        nib = (x >> (4 * i)) & 0xF
        y |= (sboxes[i][nib] & 0xF) << (4 * i)
    return y & MASK32

def round_core(right, subkey, sboxes):
    return rotl32(sbox_layer((right + subkey) & MASK32, sboxes), 11)

def apply_round(state, subkey, sboxes):
    left, right = state
    return (right & MASK32, (left ^ round_core(right, subkey, sboxes)) & MASK32)

def full_schedule(key_words):
    return list(key_words) * 3 + list(reversed(key_words))

def encrypt_rounds_from_state(state, round_keys, sboxes):
    cur = state
    for k in round_keys:
        cur = apply_round(cur, k, sboxes)
    return cur

def encrypt_block(block, key_words, sboxes):
    state = split_block(block)
    state = encrypt_rounds_from_state(state, full_schedule(key_words), sboxes)
    return join_block(*state)

def dm_compress(iv, key_words, sboxes):
    return encrypt_block(iv, key_words, sboxes) ^ iv

# --- CÁC HÀM XỬ LÝ S-BOX NGƯỢC (INVERSE) ---
def get_inv_sboxes(sboxes):
    inv = [[0]*16 for _ in range(8)]
    for i in range(8):
        for j in range(16):
            inv[i][sboxes[i][j]] = j
    return inv

def sbox_layer_inv(y, inv_sboxes):
    x = 0
    for i in range(8):
        nib_y = (y >> (4 * i)) & 0xF
        nib_x = inv_sboxes[i][nib_y]
        x |= (nib_x << (4 * i))
    return x

# --- GIAO TIẾP VỚI SERVER ---
def solve_pow(io):
    log.info("Đang giải quyết Proof of Work...")
    io.recvuntil(b"python3 <(curl -sSL https://goo.gle/kctf-pow) solve ")
    challenge = io.recvline().strip().decode()
    cmd = f"python3 <(curl -sSL https://goo.gle/kctf-pow) solve {challenge}"
    process = subprocess.run(['bash', '-c', cmd], capture_output=True, text=True)
    solution = process.stdout.strip()
    log.success(f"Đã giải PoW: {solution}")
    io.sendline(solution.encode())
    io.recvuntil(b"===================")

def get_sboxes(io):
    sboxes = [[0]*16 for _ in range(8)]
    payload = []
    for i in range(8):
        for x in range(16):
            subkey = x << (4 * i)
            payload.extend([b"1", b"0", hex(subkey)[2:].encode()])
            
    io.sendline(b"\n".join(payload))
    for i in range(8):
        for x in range(16):
            io.recvuntil(b"core = ")
            y = int(io.recvline().strip().decode(), 16)
            V = rotr32(y, 11)
            sboxes[i][x] = (V >> (4 * i)) & 0xF
    return sboxes

# --- LOGIC TẤN CÔNG INTENDED CHÍNH ---
def solve():
    io = remote("43.200.71.14", 13479)
    solve_pow(io)
    
    io.recvuntil(b"IV = ")
    iv_hex = io.recvline().strip().decode()
    IV = int(iv_hex, 16)
    log.success(f"Bắt được IV: {iv_hex}")
    
    log.info("Đang trích xuất S-Boxes...")
    sboxes = get_sboxes(io)
    inv_sboxes = get_inv_sboxes(sboxes)
    log.success("S-boxes và Inverse S-boxes chuẩn bị hoàn tất!")
    
    L0, R0 = split_block(IV)
    
    log.info("Khởi chạy Intended Attack (Davies-Meyer Collision bằng thuật toán Local Collision & Fixed Point)...")
    attempts = 0
    found = False
    
    while not found:
        # 1. Rèn K1, K2, K3 cho Local Collision
        K1 = random.randint(0, MASK32)
        K1_prime = K1 ^ (1 << 31)
        Y1 = round_core(R0, K1, sboxes)
        Y1_prime = round_core(R0, K1_prime, sboxes)
        dY1 = Y1 ^ Y1_prime
        if dY1 == 0: continue
        
        K2 = random.randint(0, MASK32)
        A = L0 ^ Y1
        A_prime = L0 ^ Y1_prime
        # Tuyệt chiêu toán học: Tự động triệt tiêu sự khác biệt cho K2
        K2_prime = (A - A_prime + K2) & MASK32
        
        Y2 = round_core(A, K2, sboxes)
        B = R0 ^ Y2
        
        K3 = -1
        # Chỉ mất cao nhất 16 vòng lặp để tìm được K3 thỏa mãn S-Box
        for _ in range(256):
            tk = random.randint(0, MASK32)
            if round_core(B, tk, sboxes) ^ round_core(B, tk ^ (1 << 31), sboxes) == dY1:
                K3 = tk
                break
                
        if K3 == -1: continue
        K3_prime = K3 ^ (1 << 31)
        
        # State tại X3
        Y3 = round_core(B, K3, sboxes)
        L3 = B
        R3 = A ^ Y3
        
        # 2. Sinh khóa K4, K5, K6 và Tính ngược (Invert) K7, K8 để ép X8 = IV
        for _ in range(4096):
            attempts += 1
            if attempts % 5000 == 0:
                log.info(f"Đang duyệt... (Đã quét {attempts} cấu hình)")
                
            K4 = random.randint(0, MASK32)
            K5 = random.randint(0, MASK32)
            K6 = random.randint(0, MASK32)
            
            L4 = R3; R4 = L3 ^ round_core(R3, K4, sboxes)
            L5 = R4; R5 = L4 ^ round_core(R4, K5, sboxes)
            L6 = R5; R6 = L5 ^ round_core(R5, K6, sboxes)
            
            # Tính K7 dựa trên S_inv
            target7 = L0 ^ L6
            req7 = rotr32(target7, 11)
            R6_inv = sbox_layer_inv(req7, inv_sboxes)
            K7 = (R6_inv - R6) & MASK32
            
            # Tính K8 dựa trên S_inv
            target8 = R0 ^ R6
            req8 = rotr32(target8, 11)
            L0_inv = sbox_layer_inv(req8, inv_sboxes)
            K8 = (L0_inv - L0) & MASK32
            
            K = [K1, K2, K3, K4, K5, K6, K7, K8]
            K_prime = [K1_prime, K2_prime, K3_prime, K4, K5, K6, K7, K8]
            
            # 3. Kiểm tra tính đối xứng tạo Collision ở cuối chu trình
            if dm_compress(IV, K, sboxes) == dm_compress(IV, K_prime, sboxes):
                log.success(f"BÙM! Đã bẻ khóa thành công bằng thuật toán của tác giả sau {attempts} lần thử nghiệm!")
                m1 = "".join(f"{w:08x}" for w in K)
                m2 = "".join(f"{w:08x}" for w in K_prime)
                found = True
                break

    log.info(f"m1: {m1}")
    log.info(f"m2: {m2}")
    
    # Gửi kết quả lên Server
    io.recvuntil(b"> ")
    io.sendline(b"2")
    io.recvuntil(b"m1 > ")
    io.sendline(m1.encode())
    io.recvuntil(b"m2 > ")
    io.sendline(m2.encode())
    
    io.recvuntil(b"Good!\n")
    flag = io.recvline().decode().strip()
    log.success(f"CỜ ĐÂY RỒI: {flag}")

if __name__ == "__main__":
    solve()
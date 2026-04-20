MASK32 = 0xFFFFFFFF
MASK64 = 0xFFFFFFFFFFFFFFFF

def dm_compress(iv, key_words, sboxes):
    return encrypt_block(iv, key_words, sboxes) ^ iv

def encrypt_block(block, key_words, sboxes):
    state = split_block(block)
    state = encrypt_rounds_from_state(state, full_schedule(key_words), sboxes)
    return join_block(*state)

def split_block(block):
    return ((block >> 32) & MASK32, block & MASK32)

def encrypt_rounds_from_state(state, round_keys, sboxes):
    cur = state
    for k in round_keys:
        cur = apply_round(cur, k, sboxes)
    return cur

def apply_round(state, subkey, sboxes):
    left, right = state
    return (right & MASK32, (left ^ round_core(right, subkey, sboxes)) & MASK32)

def round_core(right, subkey, sboxes):
    return rotl32(sbox_layer((right + subkey) & MASK32, sboxes), 11)

def rotl32(x, r):
    x &= MASK32
    return ((x << r) & MASK32) | (x >> (32 - r))

def sbox_layer(x, sboxes):
    y = 0
    for i in range(8):
        nib = (x >> (4 * i)) & 0xF
        y |= (sboxes[i][nib] & 0xF) << (4 * i)
    return y & MASK32

def full_schedule(key_words):
    if len(key_words) != 8:
        raise ValueError("expected 8 key words")
    return list(key_words) * 3 + list(reversed(key_words))

def hex_to_words(hex_string):
    s = hex_string.strip().lower()
    if s.startswith("0x"):
        s = s[2:]
    if len(s) != 64 or any(c not in "0123456789abcdef" for c in s):
        raise ValueError("message block must be 64 hex chars")
    return [int(s[i : i + 8], 16) for i in range(0, 64, 8)]

def join_block(left, right):
    return ((left & MASK32) << 32) | (right & MASK32)
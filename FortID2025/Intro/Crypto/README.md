# Crypto

## [1] PHÂN TÍCH
- Giải mã 2 file pub key ta sẽ có được 2 bộ (n, e).
- Với 2 khóa n được cung cấp, ta đoán ngay được chúng chia sẻ chung 1 số nguyên tố là p hoặc q.
- Chỉ cần tìm `gcd` của 2 số n này là có thể tính được số p, còn q1 và q2 thì chỉ việc lấy 2 số n đó chia cho q.
- Đến đây việc giải mã dễ dàng hơn khá nhiều, tuy nhiên khi mã hóa nó được sử dụng PKCS1_OAEP với SHA-256 làm thuật toán mã hóa nên khi giải mã mình cũng phải giải mã ngược lại với thuật toán SHA-256 PKCS1_OAEP.

## [2] SOLVE

```python
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Hash import SHA256
from Crypto.Util.number import inverse
from math import gcd
from pathlib import Path

# load keys
k1 = RSA.import_key(Path("key1.pub").read_bytes())
k2 = RSA.import_key(Path("key2.pub").read_bytes())
n1, n2, e = k1.n, k2.n, k1.e

# common prime
p = gcd(n1, n2)
q1, q2 = n1 // p, n2 // p

# build privkeys
def make_priv(n, p, q, e):
    phi = (p-1)*(q-1)
    d = pow(e, -1, phi)
    return RSA.construct((n, e, d, p, q), consistency_check=True)

priv1 = make_priv(n1, p, q1, e)
priv2 = make_priv(n2, p, q2, e)

# read ciphertexts (hex)
c1 = bytes.fromhex(Path("flag1.enc").read_text().strip())
c2 = bytes.fromhex(Path("flag2.enc").read_text().strip())

# OAEP with SHA-256
dec1 = PKCS1_OAEP.new(priv1, hashAlgo=SHA256).decrypt(c1)
dec2 = PKCS1_OAEP.new(priv2, hashAlgo=SHA256).decrypt(c2)

flag = (dec1 + dec2).decode()
print(flag)

```

> **Flag:** `FortID{4nd_1_Sa1d_Wh47_Ab07_4_C0mm0n_Pr1m3_F4ct0r?}`
# curl -v http://node-1.mcsc.space:11495/
import math
from Crypto.Util.number import inverse, long_to_bytes

n = int("0xb53b77acfda2d0ee31fc173b0fec24a0e57e9f48bc452bf67599a5c98e1042c1f687586b196336cf765fea1da4f1883b2757ba3f8d49f3b2848d21117308fb61795a597414fa3a97bb0d1a9550ac2f6bf902f27a475923379ad00f7e27b0f2b97571695964010f31fc64f7b775c200bde9aa0fe57abf49fb9fece3b8103936590591942737d4b7fe67a475de2c5cc92a6662efd6095c689bd263f5faec979ad1300696c4d0fbb38f2ad9c5df8cc302b204784a22c5b37815c8e8843a17e058a83d73a49d6586d12e0c13c4ca07cbeaa983a11fe97bff9e6dd284cdd393b3b7ca0f579b6741ff5067be8a7da72d1f943233f37922815d506f244755b518028b6d", 16)
e = 65537
c = int("0x26f9ff3702239250ae6a20ef818219b28a00e6447d22dca239e1117576ed8f4fcd221fee7622e3d75ead109299e3e91fd89886fb21d6c86f4ad30ff8cdabc8d6c796eb1452879ae4be322d921d382d4a6a118ddfcd1be9f418162efcf8c70684b9675816f7a2598d856847d4200aa56a85f50e22bc19486fe1a40c3642a572733fe9ca6ae58e663a636a11408685ee35967f828418d032c7094a2d860f5cb353a9ae42214ad7eafe2afad65a819f8799738630e9820d5fb74409fa20b3eeae87fbc3ac76e9f2d76decd532fc1ffcc3ffde87c60b965efa92e6119aa3ec2c9bab514056e28a63828ebeede94658c1a5ec4fbbaa249430fe32283aaece6fd4f82e", 16)

def fermat_factor(N: int):
    # Find a,b such that N = a^2 - b^2 = (a-b)(a+b)
    a = math.isqrt(N)
    if a * a < N:
        a += 1

    while True:
        b2 = a*a - N
        b = math.isqrt(b2)
        if b*b == b2:
            p = a - b
            q = a + b
            if p*q == N:
                return min(p, q), max(p, q)
        a += 1

def main():
    p, q = fermat_factor(n)
    phi = (p - 1) * (q - 1)
    d = inverse(e, phi)
    m = pow(c, d, n)
    pt = long_to_bytes(m)
    print(pt.decode(errors="replace"))

if __name__ == "__main__":
    main()
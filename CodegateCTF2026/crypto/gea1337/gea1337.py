#!/usr/bin/env python3
from functools import reduce
from secrets import randbits
from flag import flag

# ------------------------------------------------------------------------------#
# formatting routines
# ------------------------------------------------------------------------------#


def uint_to_bitlist(uint, bitlen):
    """Convert a big-endian unsigned int `uint` of length `bitlen` to a list of bits"""
    bl = bin(uint)[2:]
    if len(bl) < bitlen:
        # extend v
        bl = "0" * (bitlen - len(bl)) + bl
    return [0 if b == "0" else 1 for b in bl]


def bitlist_to_uint(bl):
    """Convert a list of bits `bl` to a big-endian unsinged integer"""
    return reduce(lambda x, y: (x << 1) + y, bl)


def byte_rev(uint, l=None):
    """revert byte order in a big endian unsigned integer"""
    if l is None:
        bl = uint.bit_length()
        l = bl // 8
        if bl % 8:
            l += 1
    #
    b = []
    for i in range(0, l):
        b.append(uint & 0xFF)
        uint >>= 8
    return reduce(lambda x, y: (x << 8) + y, b)


class LFSR:
    """parent class for all LFSR"""

    # global debugging level
    # 0: silent
    # 1: print initialized values in registers
    dbg = 0


# ------------------------------------------------------------------------------#
# f boolean function
# ------------------------------------------------------------------------------#


def f(x0, x1, x2, x3, x4, x5, x6):
    """Boolean function f on seven variables of degree 4

    section 2.1:
    x0x2x5x6 + x0x3x5x6 + x0x1x5x6 + x1x2x5x6 + x0x2x3x6 + x1x3x4x6
    + x1x3x5x6 + x0x2x4 + x0x2x3 + x0x1x3 + x0x2x6 + x0x1x4 + x0x1x6
    + x1x2x6 + x2x5x6 + x0x3x5 + x1x4x6 + x1x2x5 + x0x3 + x0x5 + x1x3
    + x1x5 + x1x6 + x0x2 + x1 + x2x3 + x2x5 + x2x6 + x4x5 + x5x6 + x2 + x3 + x5
    """
    return (
        x0 * x2 * x5 * x6
        ^ x0 * x3 * x5 * x6
        ^ x0 * x1 * x5 * x6
        ^ x1 * x2 * x5 * x6
        ^ x0 * x2 * x3 * x6
        ^ x1 * x3 * x4 * x6
        ^ x1 * x3 * x5 * x6
        ^ x0 * x2 * x4
        ^ x0 * x2 * x3
        ^ x0 * x1 * x3
        ^ x0 * x2 * x6
        ^ x0 * x1 * x4
        ^ x0 * x1 * x6
        ^ x1 * x2 * x6
        ^ x2 * x5 * x6
        ^ x0 * x3 * x5
        ^ x1 * x4 * x6
        ^ x1 * x2 * x5
        ^ x0 * x3
        ^ x0 * x5
        ^ x1 * x3
        ^ x1 * x5
        ^ x1 * x6
        ^ x0 * x2
        ^ x2 * x3
        ^ x2 * x5
        ^ x2 * x6
        ^ x4 * x5
        ^ x5 * x6
        ^ x1
        ^ x2
        ^ x3
        ^ x5
    )


# ------------------------------------------------------------------------------#
# S LFSR for initialization
# ------------------------------------------------------------------------------#


class S(LFSR):
    """64 bits S register used for initialization"""

    def __init__(self, iv, dir, key):
        """Initialize the S LFSR [64 bits]

        Args:
            iv  : 32 bits as uint32_t (big endian)
            dir : 1 bit (LSB), uint8_t
            key : 64 bits, uint64_t (big endian)
        """
        self.IN = (
            128 * [0]
            + uint_to_bitlist(key, 64)
            + uint_to_bitlist(dir, 1)
            + uint_to_bitlist(iv, 32)
        )
        self.R = 64 * [0]
        self.clk = 0

    def load(self):
        while self.IN:
            self.clock()
        if self.dbg:
            print("S init: 0x%.16x" % bitlist_to_uint(self.R))

    def clock(self):
        # compute input bit
        inp = self.R[0] ^ self.f() ^ self.IN.pop()
        # shift LFSR
        self.R = self.R[1:] + [inp]
        self.clk += 1

    def f(self):
        return f(
            self.R[3],
            self.R[12],
            self.R[22],
            self.R[38],
            self.R[42],
            self.R[55],
            self.R[63],
        )


# ------------------------------------------------------------------------------#
# LFSRs for keystream generation in GEA3
# ------------------------------------------------------------------------------#


class A(LFSR):
    """31 bits A register used for keystream generation"""

    coeffs = [1, 4, 7, 8, 11, 12, 13, 18, 21, 23, 26, 28, 29]

    def __init__(self, IN):
        self.IN = IN
        self.R = 31 * [0]
        self.clk = 0

    def load(self):
        while self.IN:
            self.clock(self.IN.pop())
        if all([b == 0 for b in self.R]):
            self.R[0] = 1
        if self.dbg:
            print("A init: 0x%.16x" % bitlist_to_uint(self.R))

    def clock(self, inp=None):
        if inp is not None:
            R0 = self.R[0] ^ inp
        else:
            R0 = self.R[0]
        # feedback
        if R0:
            for coeff in A.coeffs:
                self.R[coeff] ^= R0
        # shift
        self.R = self.R[1:] + [R0]
        self.clk += 1

    def f(self):
        return f(
            self.R[22],
            self.R[0],
            self.R[13],
            self.R[21],
            self.R[25],
            self.R[2],
            self.R[7],
        )


class B(LFSR):
    """32 bits B register used for keystream generation"""

    coeffs = [1, 3, 4, 5, 8, 13, 18, 19, 22, 23, 24, 26, 28]

    def __init__(self, IN):
        self.IN = IN
        self.R = 32 * [0]
        self.clk = 0

    def load(self):
        while self.IN:
            self.clock(self.IN.pop())
        if all([b == 0 for b in self.R]):
            self.R[0] = 1
        if self.dbg:
            print("B init: 0x%.16x" % bitlist_to_uint(self.R))

    def clock(self, inp=None):
        if inp is not None:
            R0 = self.R[0] ^ inp
        else:
            R0 = self.R[0]
        # feedback
        if R0:
            for coeff in B.coeffs:
                self.R[coeff] ^= R0
        # shift
        self.R = self.R[1:] + [R0]
        self.clk += 1

    def f(self):
        return f(
            self.R[12],
            self.R[27],
            self.R[0],
            self.R[1],
            self.R[29],
            self.R[21],
            self.R[5],
        )


class C(LFSR):
    """33 bits C register used for keystream generation"""

    coeffs = [1, 3, 4, 5, 6, 9, 10, 12, 14, 15, 17, 18, 22, 29, 31]

    def __init__(self, IN):
        self.IN = IN
        self.R = 33 * [0]
        self.clk = 0

    def load(self):
        while self.IN:
            self.clock(self.IN.pop())
        if all([b == 0 for b in self.R]):
            self.R[0] = 1
        if self.dbg:
            print("C init: 0x%.16x" % bitlist_to_uint(self.R))

    def clock(self, inp=None):
        if inp is not None:
            R0 = self.R[0] ^ inp
        else:
            R0 = self.R[0]
        # feedback
        if R0:
            for coeff in C.coeffs:
                self.R[coeff] ^= R0
        # shift
        self.R = self.R[1:] + [R0]
        self.clk += 1

    def f(self):
        return f(
            self.R[10],
            self.R[30],
            self.R[32],
            self.R[3],
            self.R[19],
            self.R[0],
            self.R[4],
        )


# ------------------------------------------------------------------------------#
# GEA1337
# ------------------------------------------------------------------------------#


class GEA1337:
    def __init__(self, iv, dir, key):
        """
        Args:
            iv : uint32 integral value
            dir: 0 or 1
            key: uint64 integral value
        """
        self._iv, self._dir, self._key = iv, dir, key
        # initialization phase
        self.S = S(iv, dir, key)
        self.S.load()
        self.A = A(list(reversed(self.S.R)))
        self.A.load()
        self.B = B(list(reversed(self.S.R[16:] + self.S.R[:16])))
        self.B.load()
        self.C = C(list(reversed(self.S.R[32:] + self.S.R[:32])))
        self.C.load()

    def gen(self, bl):
        """
        Args:
            bl : keystream length in bits required

        Returns:
            keystream : list of bits (0 or 1)
        """
        # keystream generation phase
        self.K = []
        for i in range(bl):
            self.K.append(self.A.f() ^ self.B.f() ^ self.C.f())
            self.A.clock()
            self.B.clock()
            self.C.clock()
        return list(reversed(self.K))


if __name__ == "__main__":
    key = randbits(64)
    iv = randbits(32)
    print(hex(iv))
    
    crypto = GEA1337(iv, 1, key)
    ks = crypto.gen(64)
    print(hex(bitlist_to_uint(ks)))

    assert len(flag) == 13 + 64 + 1
    assert flag[:13] == "codegate2026{" and flag[-1] == "}"
    assert flag[13:13+64].lower() == flag[13:13+64]

    val = int(flag[13:13+64], 16)
    out = val ^ bitlist_to_uint(crypto.gen(val.bit_length()))
    print(hex(out))

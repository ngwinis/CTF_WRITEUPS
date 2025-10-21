from capstone import *
from capstone.arm64 import *
import struct

binpath = "libnative-lib.so"

# offsets đã xác nhận
FUNC_OFF = 0x1A7A0
FUNC_SIZE = 1216

with open(binpath, "rb") as f:
    blob = f.read()

func = blob[FUNC_OFF:FUNC_OFF+FUNC_SIZE]

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
md.detail = True

pc = FUNC_OFF  # dùng file offset làm "pc" tạm để đọc dòng; khi cần VA, map: VA = .text.addr + (off-.text.offset)

for insn in md.disasm(func, pc):
    # In sơ lược; bạn có thể bổ sung logic nhận diện ADRP+ADD->literal, LDRB, EOR/ADD/SUB, MOVZ/MOVK...
    print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))

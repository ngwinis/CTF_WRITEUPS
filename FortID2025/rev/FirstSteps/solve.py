RET2DIGIT = {0:1,10:7,11:4,21:3,42:8,43:2,44:5,46:6,47:9,45:0}
vals = [44,47,0,10,11,43,10,42,46,21,11,0,42]
digits = ''.join(str(RET2DIGIT[v]) for v in vals)
print("FortID{" + digits + "}")

# Flag: FortID{5917427863418}
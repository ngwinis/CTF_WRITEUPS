from __future__ import annotations

from math import factorial
from pathlib import Path

SKIP = set(" \n\t\r,，.。!！?？:：;；㈫㏔")


def filtered_source(path: str) -> str:
    s = Path(path).read_text("utf-8")
    return "".join(ch for ch in s if ch not in SKIP and ord(ch) > 127)


def parse_defs(src: str) -> list[tuple[str, str]]:
    start = src.index("㐀为")
    i = start
    out: list[tuple[str, str]] = []
    while i < len(src):
        name = src[i]
        assert src[i + 1] == "为"
        depth = 1
        j = i + 2
        while j < len(src):
            c = src[j]
            if c == "为":
                depth += 1
            elif c == "矣":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        out.append((name, src[i + 2:j]))
        i = j + 1
    return out


def eval_defs(defs: list[tuple[str, str]]) -> tuple[dict[str, int], str]:
    vals: dict[str, int] = {}
    for name, expr in defs:
        if name == "旗":
            return vals, expr

        if expr.startswith("朝") and expr.endswith("暮"):
            bits = expr[1:-1]
            vals[name] = sum((1 if b == "秋" else 0) << i for i, b in enumerate(bits))
            continue

        op = expr[0]
        if op == "阶":
            vals[name] = factorial(vals[expr[1]])
        else:
            a = vals[expr[1]]
            b = vals[expr[2]]
            if op == "销":
                vals[name] = max(a - b, 0)
            elif op == "合":
                vals[name] = a + b
            elif op == "次":
                vals[name] = a * b
            elif op == "分":
                vals[name] = a // b
            elif op == "幂":
                vals[name] = a ** b
            else:
                raise ValueError((name, expr))
    raise ValueError("missing 旗")


def decode(flag_expr: str, vals: dict[str, int]) -> str:
    names = [flag_expr[i + 1] for i, ch in enumerate(flag_expr[:-1]) if ch == "有"]
    return "".join(chr(vals[n]) for n in names)


src = filtered_source("flag_riddle.txt")
defs = parse_defs(src)
vals, flag_expr = eval_defs(defs)
out = decode(flag_expr, vals)
print(out)

for line in out.splitlines():
    if line.startswith("dice{") and line.endswith("}"):
        print("\nFLAG =", line)
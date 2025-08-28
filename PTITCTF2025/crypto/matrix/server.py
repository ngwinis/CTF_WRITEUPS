from Crypto.Util.number import *
from math import ceil

P = 1_000_000_007
N = 5
FLAG = "?????????????????????????????"
def a(flag):
    b = flag.encode()
    CH = (len(b) + N*N - 1) // (N*N)     
    parts = [int.from_bytes(b[i:i+CH], "big") % P
             for i in range(0, N*N*CH, CH)]
    F = [parts[i*N:(i+1)*N] for i in range(N)]
    return F, CH

def b():
    return [[pow(k, r, P) for r in range(N)] for k in range(1, N+1)]

def c(u, F, v):
    Fv = [sum(F[r][c]*v[c] for c in range(N)) % P for r in range(N)]
    return sum((u[r] * Fv[r]) % P for r in range(N)) % P

def main():
    F, _CH = a(FLAG) 
    Pk = b()
    MAX_Q, cnt = 30, 0
    print(f"[ANS] Field: P = {P}")
    print("[ANS] Commands: 'i j' (1..5), 'done' to exit")
    while True:
        if cnt >= MAX_Q:
            print("[ANS] Out of queries. Bye!")
            break
        try:
            s = input(">> ").strip()
        except EOFError:
            break
        if not s:
            continue
        if s.lower() == "done":
            print("[ANS] See you.")
            break
        try:
            i, j = map(int, s.split())
            if 1 <= i <= N and 1 <= j <= N:
                cnt += 1
                print(f"[ANS] s_{i}{j} = {c(Pk[i-1], F, Pk[j-1])}")
            else:
                print("[ANS] i, j must be in 1..5.")
        except:
            print("[ANS] Syntax: i j  or  done")

if __name__ == "__main__":
    main()

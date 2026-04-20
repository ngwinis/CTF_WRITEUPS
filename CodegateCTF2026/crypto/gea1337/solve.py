from pycryptosat import Solver
import argparse
import time


IV = 0x4F26C090
KS64 = 0x4E1C323798A8810D
OUT = 0x8D8A3C56F7AA804B7496EFCCD842A297E5FC3C5D7CD5B13882475EED8FFD0900


def uint_to_bitlist(x, n):
    return [int(b) for b in bin(x)[2:].zfill(n)]


def bitlist_to_uint(bits):
    v = 0
    for b in bits:
        v = (v << 1) | b
    return v


def build_rows(length, coeffs, shift):
    effect = []
    for col in range(64):
        reg = [0] * length
        for step in range(64):
            inp = 1 if ((step + shift) % 64) == col else 0
            r0 = reg[0] ^ inp
            if r0:
                for coeff in coeffs:
                    reg[coeff] ^= r0
            reg = reg[1:] + [r0]
        effect.append(reg)

    rows = []
    for row in range(length):
        mask = 0
        for col in range(64):
            if effect[col][row]:
                mask |= 1 << col
        rows.append(mask)
    return rows


def rref(rows, ncols=64):
    rows = rows[:]
    pivots = []
    rank = 0
    for col in range(ncols):
        pivot = None
        for i in range(rank, len(rows)):
            if (rows[i] >> col) & 1:
                pivot = i
                break
        if pivot is None:
            continue
        rows[rank], rows[pivot] = rows[pivot], rows[rank]
        for i in range(len(rows)):
            if i != rank and ((rows[i] >> col) & 1):
                rows[i] ^= rows[rank]
        pivots.append(col)
        rank += 1
        if rank == len(rows):
            break
    return rows, pivots


def nullspace_basis(rows, ncols=64):
    rr, pivots = rref(rows, ncols)
    pivot_set = set(pivots)
    basis = []
    for free in range(ncols):
        if free in pivot_set:
            continue
        vec = 1 << free
        for row, pivot in zip(rr, pivots):
            if (row >> free) & 1:
                vec |= 1 << pivot
        basis.append(vec)
    return basis


def rank_basis(vectors):
    basis = []
    pivot_map = {}
    for vec in vectors:
        cur = vec
        while cur:
            pivot = cur.bit_length() - 1
            if pivot in pivot_map:
                cur ^= pivot_map[pivot]
            else:
                pivot_map[pivot] = cur
                basis.append(vec)
                break
    return basis, pivot_map


def in_span(vec, pivot_map):
    cur = vec
    while cur:
        pivot = cur.bit_length() - 1
        if pivot not in pivot_map:
            return False
        cur ^= pivot_map[pivot]
    return True


def compute_state_decomposition():
    a_rows = build_rows(31, [1, 4, 7, 8, 11, 12, 13, 18, 21, 23, 26, 28, 29], 0)
    b_rows = build_rows(32, [1, 3, 4, 5, 8, 13, 18, 19, 22, 23, 24, 26, 28], 16)
    c_rows = build_rows(33, [1, 3, 4, 5, 6, 9, 10, 12, 14, 15, 17, 18, 22, 29, 31], 32)

    ub = nullspace_basis(b_rows)
    tac = nullspace_basis(a_rows + c_rows)

    combo, pivots = rank_basis(ub + tac)
    v_basis = []
    for bit in range(64):
        e = 1 << bit
        if not in_span(e, pivots):
            v_basis.append(e)
            combo, pivots = rank_basis(combo + [e])
        if len(v_basis) == 8:
            break

    return ub, tac, v_basis


class BoolSolver:
    def __init__(self, threads=8):
        self.solver = Solver(threads=threads)
        self.top = 0
        self.one = self.new_var()
        self.solver.add_clause([self.one])
        self.TRUE = self.one
        self.FALSE = -self.one

    def new_var(self):
        self.top += 1
        return self.top

    def xor(self, lits):
        rhs = False
        parity = {}
        for lit in lits:
            if lit == self.FALSE:
                continue
            if lit == self.TRUE:
                rhs = not rhs
                continue
            if lit < 0:
                rhs = not rhs
                lit = -lit
            parity[lit] = parity.get(lit, 0) ^ 1
        xs = [v for v, keep in parity.items() if keep]
        if not xs:
            return self.TRUE if rhs else self.FALSE
        if len(xs) == 1:
            return -xs[0] if rhs else xs[0]
        z = self.new_var()
        self.solver.add_xor_clause(xs + [z], rhs)
        return z

    def land(self, lits):
        keep = []
        for lit in lits:
            if lit == self.FALSE:
                return self.FALSE
            if lit != self.TRUE:
                keep.append(lit)
        if not keep:
            return self.TRUE
        if len(keep) == 1:
            return keep[0]
        z = self.new_var()
        for lit in keep:
            self.solver.add_clause([-z, lit])
        self.solver.add_clause([z] + [-lit for lit in keep])
        return z


def f(bs, x0, x1, x2, x3, x4, x5, x6):
    return bs.xor(
        [
            bs.land([x0, x2, x5, x6]),
            bs.land([x0, x3, x5, x6]),
            bs.land([x0, x1, x5, x6]),
            bs.land([x1, x2, x5, x6]),
            bs.land([x0, x2, x3, x6]),
            bs.land([x1, x3, x4, x6]),
            bs.land([x1, x3, x5, x6]),
            bs.land([x0, x2, x4]),
            bs.land([x0, x2, x3]),
            bs.land([x0, x1, x3]),
            bs.land([x0, x2, x6]),
            bs.land([x0, x1, x4]),
            bs.land([x0, x1, x6]),
            bs.land([x1, x2, x6]),
            bs.land([x2, x5, x6]),
            bs.land([x0, x3, x5]),
            bs.land([x1, x4, x6]),
            bs.land([x1, x2, x5]),
            bs.land([x0, x3]),
            bs.land([x0, x5]),
            bs.land([x1, x3]),
            bs.land([x1, x5]),
            bs.land([x1, x6]),
            bs.land([x0, x2]),
            bs.land([x2, x3]),
            bs.land([x2, x5]),
            bs.land([x2, x6]),
            bs.land([x4, x5]),
            bs.land([x5, x6]),
            x1,
            x2,
            x3,
            x5,
        ]
    )


class LFSR:
    def __init__(self, bs, n, coeffs, inputs):
        self.bs = bs
        self.coeffs = coeffs
        self.R = [bs.FALSE] * n
        self.inputs = inputs[:]

    def clock(self, inp=None):
        r0 = self.R[0] if inp is None else self.bs.xor([self.R[0], inp])
        nxt = self.R[:]
        for coeff in self.coeffs:
            nxt[coeff] = self.bs.xor([nxt[coeff], r0])
        self.R = nxt[1:] + [r0]

    def load(self):
        while self.inputs:
            self.clock(self.inputs.pop())


def fa(bs, r):
    return f(bs, r[22], r[0], r[13], r[21], r[25], r[2], r[7])


def fb(bs, r):
    return f(bs, r[12], r[27], r[0], r[1], r[29], r[21], r[5])


def fc(bs, r):
    return f(bs, r[10], r[30], r[32], r[3], r[19], r[0], r[4])


def state_from_basis(bs, basis, coeff_vars):
    out = []
    for bit in range(64):
        parts = []
        for idx, vec in enumerate(basis):
            if (vec >> bit) & 1:
                parts.append(coeff_vars[idx])
        out.append(bs.xor(parts))
    return out


def build_structured_solver(threads=16):
    ub, tac, v_basis = compute_state_decomposition()
    bs = BoolSolver(threads=threads)

    uvars = [bs.new_var() for _ in range(len(ub))]
    tvars = [bs.new_var() for _ in range(len(tac))]
    vvars = [bs.new_var() for _ in range(len(v_basis))]

    s_bits = []
    for bit in range(64):
        parts = []
        for idx, vec in enumerate(ub):
            if (vec >> bit) & 1:
                parts.append(uvars[idx])
        for idx, vec in enumerate(tac):
            if (vec >> bit) & 1:
                parts.append(tvars[idx])
        for idx, vec in enumerate(v_basis):
            if (vec >> bit) & 1:
                parts.append(vvars[idx])
        s_bits.append(bs.xor(parts))

    a = LFSR(bs, 31, [1, 4, 7, 8, 11, 12, 13, 18, 21, 23, 26, 28, 29], list(reversed(s_bits)))
    b = LFSR(
        bs,
        32,
        [1, 3, 4, 5, 8, 13, 18, 19, 22, 23, 24, 26, 28],
        list(reversed(s_bits[16:] + s_bits[:16])),
    )
    c = LFSR(
        bs,
        33,
        [1, 3, 4, 5, 6, 9, 10, 12, 14, 15, 17, 18, 22, 29, 31],
        list(reversed(s_bits[32:] + s_bits[:32])),
    )
    a.load()
    b.load()
    c.load()

    out = []
    for _ in range(64):
        out.append(bs.xor([fa(bs, a.R), fb(bs, b.R), fc(bs, c.R)]))
        a.clock()
        b.clock()
        c.clock()

    for lit, bit in zip(reversed(out), uint_to_bitlist(KS64, 64)):
        bs.solver.add_clause([lit if bit else -lit])

    return {
        "bs": bs,
        "uvars": uvars,
        "tvars": tvars,
        "vvars": vvars,
        "ub": ub,
        "tac": tac,
        "v_basis": v_basis,
    }


def assumptions_for_v(vvars, value):
    bits = uint_to_bitlist(value, len(vvars))
    return [var if bit else -var for var, bit in zip(vvars, bits)]


def limited_solve(solver, assumptions=None, time_limit=None, confl_limit=None):
    kwargs = {}
    if assumptions is not None:
        kwargs["assumptions"] = assumptions
    if time_limit is not None:
        kwargs["time_limit"] = time_limit
    if confl_limit is not None:
        kwargs["confl_limit"] = confl_limit
    return solver.solve(**kwargs)


def model_bits(model, vars_):
    return [1 if model[var] else 0 for var in vars_]


def recover_s_from_components(ub, tac, v_basis, ubits, tbits, vbits):
    bits = []
    for bit in range(64):
        acc = 0
        for idx, vec in enumerate(ub):
            if ubits[idx] and ((vec >> bit) & 1):
                acc ^= 1
        for idx, vec in enumerate(tac):
            if tbits[idx] and ((vec >> bit) & 1):
                acc ^= 1
        for idx, vec in enumerate(v_basis):
            if vbits[idx] and ((vec >> bit) & 1):
                acc ^= 1
        bits.append(acc)
    return bitlist_to_uint(bits)


def structured_v_sweep(threads=16, time_limit=3.0, confl_limit=None, verbose=True):
    start_build = time.time()
    ctx = build_structured_solver(threads=threads)
    build_elapsed = time.time() - start_build

    bs = ctx["bs"]
    uvars = ctx["uvars"]
    tvars = ctx["tvars"]
    vvars = ctx["vvars"]

    if verbose:
        print(
            f"structured build done in {build_elapsed:.2f}s "
            f"(vars={bs.top}, dims=U:{len(uvars)} T:{len(tvars)} V:{len(vvars)})"
        )

    candidates = []
    stats = []
    for value in range(1 << len(vvars)):
        solve_start = time.time()
        sat, model = limited_solve(
            bs.solver,
            assumptions=assumptions_for_v(vvars, value),
            time_limit=time_limit,
            confl_limit=confl_limit,
        )
        elapsed = time.time() - solve_start
        stats.append((value, sat, elapsed))

        if verbose:
            status = "sat" if sat else "unsat/timeout"
            print(f"v={value:02x} -> {status} ({elapsed:.2f}s)")

        if sat:
            ubits = model_bits(model, uvars)
            tbits = model_bits(model, tvars)
            vbits = model_bits(model, vvars)
            s_state = recover_s_from_components(
                ctx["ub"], ctx["tac"], ctx["v_basis"], ubits, tbits, vbits
            )
            candidates.append((value, s_state))
            print(f"candidate: v={value:02x} S={s_state:016x}")

    return candidates, stats


def structured_two_stage_search(
    threads=16,
    fast_limit=0.02,
    fast_confl_limit=None,
    shortlist=16,
    deep_limit=2.0,
    deep_confl_limit=None,
    verbose=True,
):
    start_build = time.time()
    ctx = build_structured_solver(threads=threads)
    build_elapsed = time.time() - start_build

    bs = ctx["bs"]
    uvars = ctx["uvars"]
    tvars = ctx["tvars"]
    vvars = ctx["vvars"]

    if verbose:
        print(
            f"structured build done in {build_elapsed:.2f}s "
            f"(vars={bs.top}, dims=U:{len(uvars)} T:{len(tvars)} V:{len(vvars)})"
        )
        print(f"stage1: scanning all v with time_limit={fast_limit:.2f}s")

    stage1 = []
    for value in range(1 << len(vvars)):
        solve_start = time.time()
        sat, _ = limited_solve(
            bs.solver,
            assumptions=assumptions_for_v(vvars, value),
            time_limit=fast_limit,
            confl_limit=fast_confl_limit,
        )
        elapsed = time.time() - solve_start
        stage1.append((value, sat, elapsed))
        if verbose:
            status = "sat" if sat else "unsat/timeout"
            print(f"stage1 v={value:02x} -> {status} ({elapsed:.2f}s)")

    immediate = [item for item in stage1 if item[1]]
    if immediate:
        print("stage1 already found a SAT branch")

    ranked = sorted(stage1, key=lambda item: item[2], reverse=True)
    picks = ranked[:shortlist]

    if verbose:
        print("stage2 shortlist:")
        for value, sat, elapsed in picks:
            print(f"  v={value:02x} elapsed={elapsed:.2f}s sat={sat}")

    candidates = []
    for value, _, _ in picks:
        solve_start = time.time()
        sat, model = limited_solve(
            bs.solver,
            assumptions=assumptions_for_v(vvars, value),
            time_limit=deep_limit,
            confl_limit=deep_confl_limit,
        )
        elapsed = time.time() - solve_start
        status = "sat" if sat else "unsat/timeout"
        print(f"stage2 v={value:02x} -> {status} ({elapsed:.2f}s)")
        if not sat:
            continue

        ubits = model_bits(model, uvars)
        tbits = model_bits(model, tvars)
        vbits = model_bits(model, vvars)
        s_state = recover_s_from_components(
            ctx["ub"], ctx["tac"], ctx["v_basis"], ubits, tbits, vbits
        )
        print(f"candidate: v={value:02x} S={s_state:016x}")
        candidates.append((value, s_state))

    return candidates, stage1


def direct_sat(threads=16, time_limit=None):
    bs = BoolSolver(threads=threads)
    sbits = [bs.new_var() for _ in range(64)]

    a = LFSR(bs, 31, [1, 4, 7, 8, 11, 12, 13, 18, 21, 23, 26, 28, 29], list(reversed(sbits)))
    b = LFSR(
        bs,
        32,
        [1, 3, 4, 5, 8, 13, 18, 19, 22, 23, 24, 26, 28],
        list(reversed(sbits[16:] + sbits[:16])),
    )
    c = LFSR(
        bs,
        33,
        [1, 3, 4, 5, 6, 9, 10, 12, 14, 15, 17, 18, 22, 29, 31],
        list(reversed(sbits[32:] + sbits[:32])),
    )
    a.load()
    b.load()
    c.load()

    out = []
    for _ in range(64):
        out.append(bs.xor([fa(bs, a.R), fb(bs, b.R), fc(bs, c.R)]))
        a.clock()
        b.clock()
        c.clock()

    for lit, bit in zip(reversed(out), uint_to_bitlist(KS64, 64)):
        bs.solver.add_clause([lit if bit else -lit])

    start = time.time()
    sat, model = limited_solve(bs.solver, time_limit=time_limit)
    print(f"direct vars={bs.top} sat={sat} elapsed={time.time() - start:.2f}s")
    if not sat:
        return None
    s_state = bitlist_to_uint([1 if model[v] else 0 for v in sbits])
    print(f"S = {s_state:016x}")
    return s_state


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["structured", "structured-2stage", "direct"], default="structured-2stage")
    parser.add_argument("--threads", type=int, default=16)
    parser.add_argument("--time-limit", type=float, default=3.0)
    parser.add_argument("--fast-limit", type=float, default=0.02)
    parser.add_argument("--deep-limit", type=float, default=2.0)
    parser.add_argument("--fast-confl-limit", type=int, default=None)
    parser.add_argument("--deep-confl-limit", type=int, default=None)
    parser.add_argument("--confl-limit", type=int, default=None)
    parser.add_argument("--shortlist", type=int, default=16)
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args()

    print(f"iv  = {IV:08x}")
    print(f"ks  = {KS64:016x}")
    print(f"out = {OUT:064x}")

    if args.mode == "direct":
        direct_sat(threads=args.threads, time_limit=args.time_limit)
        return

    if args.mode == "structured":
        candidates, _ = structured_v_sweep(
            threads=args.threads,
            time_limit=args.time_limit,
            confl_limit=args.confl_limit,
            verbose=not args.quiet,
        )
        print(f"structured candidates: {len(candidates)}")
        return

    candidates, _ = structured_two_stage_search(
        threads=args.threads,
        fast_limit=args.fast_limit,
        fast_confl_limit=args.fast_confl_limit,
        shortlist=args.shortlist,
        deep_limit=args.deep_limit,
        deep_confl_limit=args.deep_confl_limit,
        verbose=not args.quiet,
    )
    print(f"two-stage candidates: {len(candidates)}")


if __name__ == "__main__":
    main()

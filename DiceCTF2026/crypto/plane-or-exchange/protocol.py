import hashlib
from secrets import choice, randbelow
from sympy.combinatorics import Permutation
import sympy as sp

t = sp.Symbol('t', real=True, positive=True)

def compose(p1, p2):
    return [p1[p2[i]] for i in range(len(p1))]

def inverse(p):
    inverse = [0] * len(p)
    for i, j in enumerate(p):
        inverse[j] = i
    return inverse

def validate(point):
    x, o = point
    return len(x) == len(o) and \
           Permutation(compose(x, inverse(o))).cycles == 1 and \
           sum(x[i] == o[i] for i in range(len(x))) == 0

def calculate(point):
    mat = sp.Matrix([[t**-x for x in y] for y in mine(point)])
    return mat.det(method='bareiss')*(1-t)**(1-len(point[0]))

def sweep(ap):
    l = len(ap)
    current_row = [0] * l
    matrix = []
    for pair in ap:
        c1, c2 = sorted(pair)
        diff = pair[1] - pair[0]
        if diff > 0:
            s = 1
        elif diff < 0:
            s = -1
        else:
            s = 0
        for c in range(c1, c2):
            current_row[c] += s
        matrix.append(list(current_row))
    return matrix

def mine(point):
    x, o = point
    return sweep([*zip(x, o)])

def connect(g1, g2):
    x1, o1 = g1
    x2, o2 = g2
    l = len(x1)
    new_x = list(x1) + [v + l for v in x2]
    new_o = list(o1) + [v + l for v in o2]
    idx1 = l - 1
    idx2 = l
    new_x[idx1], new_x[idx2] = new_x[idx2], new_x[idx1]
    return (new_x, new_o)

def normalize(calculation):
    poly = sp.expand(sp.simplify(calculation))
    all_exponents = [term.as_coeff_exponent(t)[1] for term in poly.as_ordered_terms()]
    min_exp = min(all_exponents)
    poly *= t**(-min_exp)
    poly = sp.expand(sp.simplify(poly))
    if poly.coeff(t,0)<0:
        poly *= -1
    return poly

def slide1(data):
    def check(x1, o1, x2, o2):
        low1, high1 = min(x1, o1), max(x1, o1)
        low2, high2 = min(x2, o2), max(x2, o2)
        if high1 < low2 or high2 < low1:
            return True
        if (low1 > low2 and high1 < high2) or (low2 > low1 and high2 < high1):
            return True
        return False
    x, o = data
    idx = randbelow(len(x)-1)
    if check(x[idx], o[idx], x[idx+1], o[idx+1]):
        x[idx], x[idx+1] = x[idx+1], x[idx]
        o[idx], o[idx+1] = o[idx+1], o[idx]
    return (x, o)

def slide2(data):
    x_cols, o_cols = data
    n = len(x_cols)
    j = randbelow(n - 1)
    x_pos_j = x_cols.index(j)
    o_pos_j = o_cols.index(j)
    x_pos_j1 = x_cols.index(j + 1)
    o_pos_j1 = o_cols.index(j + 1)
    low_j, high_j = min(x_pos_j, o_pos_j), max(x_pos_j, o_pos_j)
    low_j1, high_j1 = min(x_pos_j1, o_pos_j1), max(x_pos_j1, o_pos_j1)
    valid = False
    if high_j < low_j1 or high_j1 < low_j:
        valid = True
    elif (low_j > low_j1 and high_j < high_j1) or (low_j1 > low_j and high_j1 < high_j):
        valid = True
    if valid:
        new_x = list(x_cols)
        new_o = list(o_cols)
        new_x[x_pos_j] = j + 1
        new_x[x_pos_j1] = j
        new_o[o_pos_j] = j + 1
        new_o[o_pos_j1] = j
        return (new_x, new_o)
    return data

def shuffle(data):
    x, o = data
    n = len(x)
    opt = randbelow(4)
    if opt==0:
        x = [(x+1)%n for x in x]
        o = [(o+1)%n for o in o]
    if opt==1:
        x = [(x+n-1)%n for x in x]
        o = [(o+n-1)%n for o in o]
    if opt==2:
        x = x[-1:] + x[:-1]
        o = o[-1:] + o[:-1]
    if opt==3:
        x = x[1:] + x[:1]
        o = o[1:] + o[:1]
    return (x, o)

def scramble(data, iter):
    new = [[*data[0]], [*data[1]]]
    for _ in range(iter):
        f = choice([
            slide1,
            slide2,
            shuffle
        ])
        new = f(new)
    return new

def derive_public_key(my_priv, public_info):
    return scramble(connect(public_info, my_priv), 1000)

def derive_shared_secret(my_priv, their_pub):
    return hashlib.sha256(str(normalize(calculate(connect(my_priv, their_pub)))).encode()).hexdigest()

def encrypt(flag, shared_secret):
    key = bytes.fromhex(shared_secret)
    while len(key) < len(flag):
        key += hashlib.sha256(key).digest()
    return bytes(a^b for a, b in zip(flag.encode(), key)).hex()

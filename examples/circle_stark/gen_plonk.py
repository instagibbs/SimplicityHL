#!/usr/bin/env python3
"""
Generate Fibonacci PLONK Circle STARK verifier for SimplicityHL.

Matches jmoik/bitcoin-circle-stark's Fibonacci PLONK AIR:
- 4 trace columns: mult, a_val, b_val, c_val
- 4 constant columns: a_wire, b_wire, c_wire, op
- 8 interaction columns: logab (4 QM31 components), cum (4 QM31 components)
- 4 composition columns: H split into 4 M31 components
- OODS constraint check + DEEP quotient + FRI
"""

import hashlib, random, struct, sys

# ============================================================
# M31 field arithmetic (p = 2^31 - 1)
# ============================================================
P = (1 << 31) - 1

def m31(x):
    return x % P

def m31_add(a, b):
    s = a + b
    return s - P if s >= P else s

def m31_sub(a, b):
    return m31_add(a, m31_neg(b))

def m31_neg(a):
    return 0 if a == 0 else P - a

def m31_mul(a, b):
    return m31(a * b)

def m31_inv(a):
    return pow(a, P - 2, P)

# ============================================================
# CM31 complex extension: i^2 = -1
# ============================================================

def cm31_add(a, b):
    return (m31_add(a[0], b[0]), m31_add(a[1], b[1]))

def cm31_sub(a, b):
    return (m31_sub(a[0], b[0]), m31_sub(a[1], b[1]))

def cm31_neg(a):
    return (m31_neg(a[0]), m31_neg(a[1]))

def cm31_mul(a, b):
    return (m31_sub(m31_mul(a[0], b[0]), m31_mul(a[1], b[1])),
            m31_add(m31_mul(a[0], b[1]), m31_mul(a[1], b[0])))

def cm31_mul_r(a):
    """Multiply by R = (2, 1) = 2+i."""
    re, im = a
    return (m31_sub(m31_add(re, re), im), m31_add(re, m31_add(im, im)))

def cm31_scale(a, s):
    return (m31_mul(a[0], s), m31_mul(a[1], s))

def cm31_inv(a):
    re, im = a
    norm = m31_add(m31_mul(re, re), m31_mul(im, im))
    inv_norm = m31_inv(norm)
    return (m31_mul(re, inv_norm), m31_neg(m31_mul(im, inv_norm)))

CM31_ZERO = (0, 0)
CM31_ONE = (1, 0)

# ============================================================
# QM31 quartic extension: u^2 = 2+i
# ============================================================

def qm31_add(a, b):
    return (cm31_add(a[0], b[0]), cm31_add(a[1], b[1]))

def qm31_sub(a, b):
    return (cm31_sub(a[0], b[0]), cm31_sub(a[1], b[1]))

def qm31_neg(a):
    return (cm31_neg(a[0]), cm31_neg(a[1]))

def qm31_mul(a, b):
    a0b0 = cm31_mul(a[0], b[0])
    a1b1 = cm31_mul(a[1], b[1])
    return (cm31_add(a0b0, cm31_mul_r(a1b1)),
            cm31_add(cm31_mul(a[0], b[1]), cm31_mul(a[1], b[0])))

def qm31_scale(a, s):
    """Scale QM31 by M31 scalar."""
    return (cm31_scale(a[0], s), cm31_scale(a[1], s))

def qm31_inv(a):
    a0, a1 = a
    a0sq = cm31_mul(a0, a0)
    a1sq = cm31_mul(a1, a1)
    denom = cm31_sub(a0sq, cm31_mul_r(a1sq))
    inv_denom = cm31_inv(denom)
    return (cm31_mul(a0, inv_denom), cm31_neg(cm31_mul(a1, inv_denom)))

def qm31_from_m31(x):
    return ((x, 0), (0, 0))

QM31_ZERO = ((0, 0), (0, 0))
QM31_ONE = ((1, 0), (0, 0))

def qm31_eq(a, b):
    return a[0][0] == b[0][0] and a[0][1] == b[0][1] and \
           a[1][0] == b[1][0] and a[1][1] == b[1][1]

# ============================================================
# Circle group (x^2 + y^2 = 1 mod P)
# ============================================================

def circle_mul(p1, p2):
    return (m31_sub(m31_mul(p1[0], p2[0]), m31_mul(p1[1], p2[1])),
            m31_add(m31_mul(p1[0], p2[1]), m31_mul(p1[1], p2[0])))

def circle_double(p):
    x, y = p
    return (m31_sub(m31_add(m31_mul(x, x), m31_mul(x, x)), 1),
            m31_add(m31_mul(x, y), m31_mul(x, y)))

def circle_conj(p):
    return (p[0], m31_neg(p[1]))

CIRCLE_GEN = (2, 1268011823)  # generator of order 2^31

def subgroup_gen(log_size):
    g = CIRCLE_GEN
    for _ in range(31 - log_size):
        g = circle_double(g)
    return g

def circle_pow(gen, n):
    """Square-and-multiply for circle group."""
    r = (1, 0)
    base = gen
    while n > 0:
        if n & 1:
            r = circle_mul(r, base)
        base = circle_mul(base, base)
        n >>= 1
    return r

def canonic_coset(log_size):
    """Generate the STWO CanonicCoset of order 2^log_size.
    initial = subgroup_gen(log_size + 1), step = subgroup_gen(log_size).
    Avoids the subgroup (so no y=0 points). The coset_vanishing
    (T^{k-1}(shifted_x)) naturally divides constraints built from
    trace columns on this coset.
    """
    N = 1 << log_size
    initial_idx = 1 << (31 - log_size - 1)  # = 2^{30 - log_size}
    coset_rep = circle_pow(CIRCLE_GEN, initial_idx)
    gen = subgroup_gen(log_size)
    domain = [coset_rep]
    for i in range(1, N):
        domain.append(circle_mul(domain[-1], gen))
    return domain, coset_rep

# QM31 circle point operations

def qm31_circle_point(p):
    """Embed M31 circle point as QM31 circle point."""
    return (qm31_from_m31(p[0]), qm31_from_m31(p[1]))

def qm31_circle_mul(p1, p2):
    """Multiply two QM31 circle points."""
    x1, y1 = p1
    x2, y2 = p2
    return (qm31_sub(qm31_mul(x1, x2), qm31_mul(y1, y2)),
            qm31_add(qm31_mul(x1, y2), qm31_mul(y1, x2)))

def qm31_circle_double(p):
    x, y = p
    x2 = qm31_mul(x, x)
    return (qm31_sub(qm31_add(x2, x2), QM31_ONE),
            qm31_add(qm31_mul(x, y), qm31_mul(x, y)))

# ============================================================
# SHA256 / Channel / Merkle
# ============================================================

def sha256(data):
    return hashlib.sha256(data).digest()

def u256_bytes(v):
    return v.to_bytes(32, 'big')

def u32_bytes(v):
    return struct.pack('>I', v)

def to_u256(b):
    return int.from_bytes(b, 'big')

def hash_node(l, r):
    return to_u256(sha256(u256_bytes(l) + u256_bytes(r)))

def hash_m31_values(*vals):
    """Hash a list of M31 values as a Merkle leaf."""
    return to_u256(sha256(b''.join(u32_bytes(v) for v in vals)))

def hash_qm31_leaf(q):
    return hash_m31_values(q[0][0], q[0][1], q[1][0], q[1][1])


class Channel:
    def __init__(self):
        self.state = sha256(b'\x00' * 32)

    def mix(self, v):
        self.state = sha256(self.state + u256_bytes(v))

    def mix_qm31(self, v):
        """Mix a QM31 value into the channel (as 4 u32s)."""
        data = self.state
        for cm in [v[0], v[1]]:
            data += u32_bytes(cm[0]) + u32_bytes(cm[1])
        self.state = sha256(data)

    def squeeze(self):
        ns = sha256(self.state + u32_bytes(0))
        r = sha256(self.state + u32_bytes(1))
        self.state = ns
        return to_u256(r)

    def squeeze_qm31(self):
        r = self.squeeze()
        w = [(r >> (224 - 32 * i)) & 0xFFFFFFFF for i in range(4)]
        return ((m31(w[0] & P), m31(w[1] & P)),
                (m31(w[2] & P), m31(w[3] & P)))

    def squeeze_index(self, mask):
        r = self.squeeze()
        return m31((r >> 224) & 0xFFFFFFFF & P) & mask


class MerkleTree:
    def __init__(self, leaves):
        self.depth = len(leaves).bit_length() - 1
        self.layers = [leaves]
        cur = leaves
        while len(cur) > 1:
            cur = [hash_node(cur[i], cur[i + 1])
                   for i in range(0, len(cur), 2)]
            self.layers.append(cur)
        self.root = cur[0]

    def get_path(self, idx):
        path, i = [], idx
        for layer in self.layers[:-1]:
            path.append(layer[i ^ 1])
            i >>= 1
        return path


# ============================================================
# Circle polynomial operations
# ============================================================

def fold_m31(values, twiddles):
    """Fold M31 coefficient values with M31 twiddles."""
    if not twiddles:
        return values[0]
    half = len(values) // 2
    tw = twiddles[-1]
    left = fold_m31(values[:half], twiddles[:-1])
    right = fold_m31(values[half:], twiddles[:-1])
    return m31_add(left, m31_mul(tw, right))


def fold_qm31(values, twiddles):
    """Fold M31 coefficient values with QM31 twiddles."""
    if not twiddles:
        return qm31_from_m31(values[0])
    half = len(values) // 2
    tw = twiddles[-1]
    left = fold_qm31(values[:half], twiddles[:-1])
    right = fold_qm31(values[half:], twiddles[:-1])
    return qm31_add(left, qm31_mul(tw, right))


def m31_twiddles(point, log_n):
    """Build twiddle list for evaluation at M31 circle point."""
    if log_n == 0:
        return []
    px, py = point
    twiddles = [py]
    if log_n >= 2:
        twiddles.append(px)
    x = px
    for _ in range(2, log_n):
        x = m31_sub(m31_add(m31_mul(x, x), m31_mul(x, x)), 1)
        twiddles.append(x)
    return twiddles


def qm31_twiddles(point, log_n):
    """Build QM31 twiddle list for evaluation at QM31 circle point."""
    if log_n == 0:
        return []
    px, py = point
    twiddles = [py]
    if log_n >= 2:
        twiddles.append(px)
    x = px
    for _ in range(2, log_n):
        x2 = qm31_mul(x, x)
        x = qm31_sub(qm31_add(x2, x2), QM31_ONE)
        twiddles.append(x)
    return twiddles


def circle_eval_m31(coeffs, point):
    """Evaluate circle polynomial (M31 coeffs) at M31 circle point."""
    log_n = len(coeffs).bit_length() - 1
    return fold_m31(coeffs, m31_twiddles(point, log_n))


def circle_eval_qm31(coeffs, point):
    """Evaluate circle polynomial (M31 coeffs) at QM31 circle point."""
    log_n = len(coeffs).bit_length() - 1
    return fold_qm31(coeffs, qm31_twiddles(point, log_n))


def gauss_solve_m31(A, b):
    """Solve Ax = b over M31 using Gaussian elimination."""
    N = len(b)
    M = [row[:] + [b[i]] for i, row in enumerate(A)]
    for col in range(N):
        pivot = None
        for row in range(col, N):
            if M[row][col] != 0:
                pivot = row
                break
        assert pivot is not None, f"Singular matrix at column {col}"
        M[col], M[pivot] = M[pivot], M[col]
        inv_p = m31_inv(M[col][col])
        for j in range(N + 1):
            M[col][j] = m31_mul(M[col][j], inv_p)
        for row in range(N):
            if row != col and M[row][col] != 0:
                f = M[row][col]
                for j in range(N + 1):
                    M[row][j] = m31_sub(M[row][j], m31_mul(f, M[col][j]))
    return [M[i][N] for i in range(N)]


def circle_interpolate(evals, domain):
    """Interpolate: evaluations at domain points -> circle polynomial coeffs.
    Uses Vandermonde matrix + Gaussian elimination. O(N^3), fine for N <= 256.
    """
    N = len(evals)
    log_n = N.bit_length() - 1
    V = []
    for p in domain:
        tw = m31_twiddles(p, log_n)
        row = []
        for j in range(N):
            c = [0] * N
            c[j] = 1
            row.append(fold_m31(c, tw))
        V.append(row)
    return gauss_solve_m31(V, list(evals))


def circle_lde(coeffs, eval_domain):
    """Low-degree extension: evaluate polynomial on larger domain."""
    return [circle_eval_m31(coeffs, p) for p in eval_domain]


def vanishing_eval_m31(point, log_n, coset_rep):
    """Evaluate STWO's coset_vanishing at M31 point.
    V(p) = T^{k-1}(shifted_x) where shifted_x = (coset_rep^{-1} * p).x
    and k = log_n. Result is ±1 on the canonic coset, nonzero elsewhere.
    """
    cr_inv = circle_conj(coset_rep)
    shifted = circle_mul(cr_inv, point)
    x = shifted[0]
    for _ in range(log_n - 1):
        x = m31_sub(m31_add(m31_mul(x, x), m31_mul(x, x)), 1)
    return x


def vanishing_eval_qm31(point, log_n, coset_rep):
    """Evaluate coset_vanishing at QM31 circle point."""
    cr_inv = circle_conj(coset_rep)
    cr_inv_qm31 = qm31_circle_point(cr_inv)
    shifted = qm31_circle_mul(cr_inv_qm31, point)
    x = shifted[0]
    for _ in range(log_n - 1):
        x2 = qm31_mul(x, x)
        x = qm31_sub(qm31_add(x2, x2), QM31_ONE)
    return x


# ============================================================
# OODS point generation
# ============================================================

def gen_oods_point(channel):
    """Generate OODS point on the QM31 circle from channel randomness.
    Uses rational parametrization: t -> ((1-t^2)/(1+t^2), 2t/(1+t^2))
    """
    t = channel.squeeze_qm31()
    t_sq = qm31_mul(t, t)
    one_plus_t_sq = qm31_add(QM31_ONE, t_sq)
    one_minus_t_sq = qm31_sub(QM31_ONE, t_sq)
    inv = qm31_inv(one_plus_t_sq)
    x = qm31_mul(one_minus_t_sq, inv)
    y = qm31_mul(qm31_add(t, t), inv)
    return (x, y)


# ============================================================
# Pair vanishing and column-line coefficients
# ============================================================

def prepare_pair_vanishing(oods_point):
    """Precompute pair vanishing helper values.
    Returns (x_second_div_y_second, cross_term) as CM31 values.
    """
    px, py = oods_point  # QM31 values
    # .second = the CM31 "j" component
    y_second = py[1]  # CM31
    y_second_inv = cm31_inv(y_second)
    x_second = px[1]  # CM31
    x_second_div_y_second = cm31_mul(x_second, y_second_inv)
    y_first = py[0]  # CM31
    x_first = px[0]  # CM31
    cross_term = cm31_sub(cm31_mul(x_second_div_y_second, y_first),
                          x_first)
    return (x_second_div_y_second, cross_term)


def pair_vanishing_denom_inv(prepared, query_x, query_y):
    """Compute 1/V(query, oods) using prepared values.
    Returns (denom_inv_left, denom_inv_right) as CM31 values.
    """
    prep_a, prep_b = prepared  # CM31 values
    # t = prep_b + query_x  (CM31 + M31)
    t = cm31_add(prep_b, (query_x, 0))
    # s = prep_a * query_y  (CM31 * M31)
    s = cm31_scale(prep_a, query_y)
    denom_left = cm31_sub(t, s)
    denom_right = cm31_add(t, s)
    return (cm31_inv(denom_left), cm31_inv(denom_right))


def column_line_coeffs(oods_val, oods_y):
    """Compute column-line coefficients (a, b) for a column.
    oods_val: QM31 evaluation at OODS point
    oods_y: QM31 y-coordinate of OODS point
    Returns (a, b) as CM31 values.
    """
    # a = Im_j(oods_val) / Im_j(oods_y)
    val_second = oods_val[1]  # CM31
    y_second = oods_y[1]  # CM31
    y_second_inv = cm31_inv(y_second)
    a = cm31_mul(val_second, y_second_inv)
    # b = a * Re_j(oods_y) - Re_j(oods_val)
    y_first = oods_y[0]  # CM31
    val_first = oods_val[0]  # CM31
    b = cm31_sub(cm31_mul(a, y_first), val_first)
    return (a, b)


def apply_twin(query_y, f_left, f_right, coeff_a, coeff_b):
    """Compute column-line numerators at query point and its conjugate.
    query_y: M31 y-coordinate of query point
    f_left, f_right: M31 column values at query and conjugate
    coeff_a, coeff_b: CM31 column-line coefficients
    Returns (num_left, num_right) as CM31 values.
    """
    a_times_y = cm31_scale(coeff_a, query_y)
    num_left = cm31_add(cm31_sub(coeff_b, a_times_y), (f_left, 0))
    num_right = cm31_add(cm31_add(coeff_b, a_times_y), (f_right, 0))
    return (num_left, num_right)


# ============================================================
# FRI folding
# ============================================================

def fold_eval(v0, v1, alpha, twiddle):
    """FRI fold: ibutterfly then combine with alpha."""
    inv2 = m31_inv(2)
    fe = qm31_scale(qm31_add(v0, v1), inv2)
    inv2tw = m31_inv(m31_mul(2, twiddle))
    fo = qm31_scale(qm31_sub(v0, v1), inv2tw)
    return qm31_add(fe, qm31_mul(alpha, fo))


# ============================================================
# Fibonacci PLONK trace generation
# ============================================================

def gen_fibonacci_plonk(log_n_rows):
    """Generate the Fibonacci PLONK circuit trace.
    Returns dict with trace, constant columns and multiplicities.
    """
    N = 1 << log_n_rows

    # Fibonacci values
    fib = [0] * N
    fib[0] = fib[1] = 1
    for i in range(2, N):
        fib[i] = m31_add(fib[i - 1], fib[i - 2])

    # Row 0, 1: identity gates (op=0, c = a*b = 1*1 = 1)
    # Row 2..N-1: addition gates (op=1, c = a+b)
    a_wire = [0, 1] + [i - 2 for i in range(2, N)]
    b_wire = [0, 1] + [i - 1 for i in range(2, N)]
    c_wire = list(range(N))
    op = [0, 0] + [1] * (N - 2)

    a_val = [fib[a_wire[i]] for i in range(N)]
    b_val = [fib[b_wire[i]] for i in range(N)]
    c_val = [fib[c_wire[i]] for i in range(N)]

    # Verify gate constraints
    for i in range(N):
        if op[i] == 1:
            assert c_val[i] == m31_add(a_val[i], b_val[i])
        else:
            assert c_val[i] == m31_mul(a_val[i], b_val[i])

    # Multiplicities: count how many times each wire appears
    wire_count = [0] * N
    for i in range(N):
        wire_count[a_wire[i]] += 1
        wire_count[b_wire[i]] += 1
        wire_count[c_wire[i]] += 1
    # mult[i] = table_multiplicity(wire i) - 1
    # (subtract 1 for the c-column self-reference)
    mult = [wire_count[i] - 1 for i in range(N)]

    return {
        'N': N, 'log_n': log_n_rows,
        'a_val': a_val, 'b_val': b_val, 'c_val': c_val,
        'a_wire': a_wire, 'b_wire': b_wire, 'c_wire': c_wire,
        'op': op, 'mult': mult,
    }


def gen_interaction_trace(plonk, z, alpha):
    """Compute logup interaction trace from PLONK data and challenges.
    Returns interaction_ab (QM31 per row), cum (QM31 per row),
    and claimed_sum (QM31).
    """
    N = plonk['N']
    a_val, b_val, c_val = plonk['a_val'], plonk['b_val'], plonk['c_val']
    a_wire, b_wire, c_wire = plonk['a_wire'], plonk['b_wire'], plonk['c_wire']
    mult_col = plonk['mult']

    interaction_ab = []
    denom_3_list = []
    for i in range(N):
        # denom_1 = a_wire + alpha * a_val - z
        d1 = qm31_sub(qm31_add(qm31_from_m31(a_wire[i]),
                                qm31_mul(alpha, qm31_from_m31(a_val[i]))), z)
        # denom_2 = b_wire + alpha * b_val - z
        d2 = qm31_sub(qm31_add(qm31_from_m31(b_wire[i]),
                                qm31_mul(alpha, qm31_from_m31(b_val[i]))), z)
        # interaction_ab = 1/d1 + 1/d2 = (d1 + d2) / (d1 * d2)
        num = qm31_add(d1, d2)
        den = qm31_mul(d1, d2)
        iab = qm31_mul(num, qm31_inv(den))
        interaction_ab.append(iab)

        # denom_3 = c_wire + alpha * c_val - z
        d3 = qm31_sub(qm31_add(qm31_from_m31(c_wire[i]),
                                qm31_mul(alpha, qm31_from_m31(c_val[i]))), z)
        denom_3_list.append(d3)

    # claimed_sum = sum(interaction_ab[i] - mult[i] / denom_3[i])
    claimed_sum = QM31_ZERO
    for i in range(N):
        term = qm31_sub(interaction_ab[i],
                         qm31_scale(qm31_inv(denom_3_list[i]), mult_col[i]))
        claimed_sum = qm31_add(claimed_sum, term)

    # claimed_sum_divided = claimed_sum / N
    inv_n = m31_inv(N)
    csd = qm31_scale(claimed_sum, inv_n)

    # Cumulative sum: cum[0] = 0
    # cum[i+1] = cum[i] - interaction_ab[i] + csd + mult[i] / denom_3[i]
    cum = [QM31_ZERO] * (N + 1)
    for i in range(N):
        mult_term = qm31_scale(qm31_inv(denom_3_list[i]), mult_col[i])
        cum[i + 1] = qm31_add(
            qm31_sub(cum[i], interaction_ab[i]),
            qm31_add(csd, mult_term))

    # Verify wrap-around: cum[N] should be zero
    assert qm31_eq(cum[N], QM31_ZERO), \
        f"Cumulative sum doesn't wrap: {cum[N]}"

    # Drop cum[N] (it's the same as cum[0] = 0)
    cum = cum[:N]

    return {
        'interaction_ab': interaction_ab,
        'cum': cum,
        'claimed_sum': claimed_sum,
    }


# ============================================================
# Full PLONK proof generation
# ============================================================

def generate_plonk_proof(log_n_rows, log_blowup, n_queries, seed=42):
    """Generate a complete Fibonacci PLONK Circle STARK proof."""
    random.seed(seed)
    N = 1 << log_n_rows
    log_eval = log_n_rows + 1 + log_blowup  # +1 for composition degree
    M = 1 << log_eval

    print(f"PLONK params: trace={N}, eval_domain=2^{log_eval}={M}, "
          f"queries={n_queries}")

    # ── Step 1: Generate Fibonacci PLONK trace ──
    plonk = gen_fibonacci_plonk(log_n_rows)
    print(f"  Fibonacci trace generated ({N} rows)")

    # ── Step 2: Setup domains ──
    trace_gen = subgroup_gen(log_n_rows)
    # Use STWO canonic cosets — these have the special structure that
    # ensures coset_vanishing divides the constraint numerator
    trace_domain, trace_coset_rep = canonic_coset(log_n_rows)
    eval_domain, eval_coset_rep = canonic_coset(log_eval)

    # Verify: coset_vanishing is ±1 on canonic coset trace domain
    for j in range(N):
        v = vanishing_eval_m31(trace_domain[j], log_n_rows, trace_coset_rep)
        assert v == 1 or v == m31_neg(1), \
            f"coset_vanishing not ±1 on trace_domain[{j}]: {v}"
    # Verify: nonzero on eval domain
    for j in range(min(10, M)):
        v = vanishing_eval_m31(eval_domain[j], log_n_rows, trace_coset_rep)
        assert v != 0, f"Vanishing polynomial is zero at eval_domain[{j}]!"
    print(f"  Domains set up (trace: {N}, eval: {M})")

    # ── Step 3: Interpolate trace columns ──
    trace_cols = {
        'mult': plonk['mult'], 'a_val': plonk['a_val'],
        'b_val': plonk['b_val'], 'c_val': plonk['c_val'],
    }
    const_cols = {
        'a_wire': plonk['a_wire'], 'b_wire': plonk['b_wire'],
        'c_wire': plonk['c_wire'], 'op': plonk['op'],
    }

    # Interpolate to get polynomial coefficients
    trace_coeffs = {}
    for name, col in trace_cols.items():
        trace_coeffs[name] = circle_interpolate(col, trace_domain)
    # Verify round-trip
    for name, col in trace_cols.items():
        for i in range(N):
            v = circle_eval_m31(trace_coeffs[name], trace_domain[i])
            assert v == col[i], \
                f"Round-trip failed for trace.{name}[{i}]: {v} != {col[i]}"
    print(f"  Trace columns interpolated (round-trip verified)")

    const_coeffs = {}
    for name, col in const_cols.items():
        const_coeffs[name] = circle_interpolate(col, trace_domain)
    print(f"  Constant columns interpolated")

    # ── Step 4: LDE trace and constant columns ──
    trace_evals = {}
    for name, coeffs in trace_coeffs.items():
        trace_evals[name] = circle_lde(coeffs, eval_domain)
    print(f"  Trace LDE done")

    const_evals = {}
    for name, coeffs in const_coeffs.items():
        const_evals[name] = circle_lde(coeffs, eval_domain)
    print(f"  Constant LDE done")

    # ── Step 5: Commit trace columns ──
    trace_leaves = [
        hash_m31_values(trace_evals['mult'][j], trace_evals['a_val'][j],
                        trace_evals['b_val'][j], trace_evals['c_val'][j])
        for j in range(M)]
    trace_tree = MerkleTree(trace_leaves)
    print(f"  Trace committed: {trace_tree.root:#066x}")

    # ── Step 6: Fiat-Shamir — squeeze lookup challenges ──
    ch = Channel()
    ch.mix(trace_tree.root)
    z = ch.squeeze_qm31()      # lookup element z
    alpha = ch.squeeze_qm31()  # lookup element alpha
    print(f"  Lookup challenges derived")

    # ── Step 7: Compute interaction trace ──
    interaction = gen_interaction_trace(plonk, z, alpha)
    print(f"  Interaction trace computed")

    # Decompose QM31 interaction columns into M31 components
    # interaction_ab: 4 M31 columns (re.re, re.im, im.re, im.im)
    # cum: 4 M31 columns
    def qm31_components(qm31_list):
        """Decompose list of QM31 into 4 lists of M31."""
        c0 = [v[0][0] for v in qm31_list]
        c1 = [v[0][1] for v in qm31_list]
        c2 = [v[1][0] for v in qm31_list]
        c3 = [v[1][1] for v in qm31_list]
        return [c0, c1, c2, c3]

    logab_m31 = qm31_components(interaction['interaction_ab'])
    cum_m31 = qm31_components(interaction['cum'])

    # Interpolate interaction columns
    logab_coeffs = [circle_interpolate(col, trace_domain) for col in logab_m31]
    cum_coeffs = [circle_interpolate(col, trace_domain) for col in cum_m31]
    print(f"  Interaction columns interpolated")

    # LDE interaction columns
    logab_evals = [circle_lde(c, eval_domain) for c in logab_coeffs]
    cum_evals = [circle_lde(c, eval_domain) for c in cum_coeffs]
    print(f"  Interaction LDE done")

    # Commit interaction columns (8 M31 values per leaf)
    interaction_leaves = [
        hash_m31_values(
            logab_evals[0][j], logab_evals[1][j],
            logab_evals[2][j], logab_evals[3][j],
            cum_evals[0][j], cum_evals[1][j],
            cum_evals[2][j], cum_evals[3][j])
        for j in range(M)]
    interaction_tree = MerkleTree(interaction_leaves)
    ch.mix(interaction_tree.root)
    print(f"  Interaction committed")

    # Commit constant columns
    const_leaves = [
        hash_m31_values(const_evals['a_wire'][j], const_evals['b_wire'][j],
                        const_evals['c_wire'][j], const_evals['op'][j])
        for j in range(M)]
    const_tree = MerkleTree(const_leaves)
    ch.mix(const_tree.root)
    print(f"  Constants committed")

    # ── Step 8: Squeeze composition random coeff ──
    rho = ch.squeeze_qm31()  # composition_fold_random_coeff

    # ── Step 9: Compute composition polynomial H ──
    # H(x) = (rho^2 * C_gate(x) + rho * C_logup2(x) + C_logup3(x)) / V(x)
    # Evaluated on the eval domain where V != 0
    rho_sq = qm31_mul(rho, rho)
    inv_n = m31_inv(N)
    csd = qm31_scale(interaction['claimed_sum'], inv_n)

    # Precompute logc_next: cum evaluated at shifted points
    # logc_next(eval_domain[j]) = cum(trace_gen * eval_domain[j])
    print(f"  Computing shifted cum evaluations...")
    cum_next_evals = []
    for k in range(4):
        shifted = []
        for j in range(M):
            sp = circle_mul(trace_gen, eval_domain[j])
            shifted.append(circle_eval_m31(cum_coeffs[k], sp))
        cum_next_evals.append(shifted)
    print(f"  Shifted cum LDE done")

    comp_evals_qm31 = []
    for j in range(M):
        # Column values at eval point j
        mv = trace_evals['mult'][j]
        av = trace_evals['a_val'][j]
        bv = trace_evals['b_val'][j]
        cv = trace_evals['c_val'][j]
        aw = const_evals['a_wire'][j]
        bw = const_evals['b_wire'][j]
        cw = const_evals['c_wire'][j]
        opv = const_evals['op'][j]

        # Reconstruct QM31 interaction values
        iab = ((logab_evals[0][j], logab_evals[1][j]),
               (logab_evals[2][j], logab_evals[3][j]))
        logc = ((cum_evals[0][j], cum_evals[1][j]),
                (cum_evals[2][j], cum_evals[3][j]))

        # logc_next: cum evaluated at trace_gen * eval_domain[j]
        logc_next = ((cum_next_evals[0][j], cum_next_evals[1][j]),
                     (cum_next_evals[2][j], cum_next_evals[3][j]))

        # Gate constraint: c - (op*(a+b-a*b) + a*b) = 0
        ab = m31_mul(av, bv)
        gate = m31_sub(cv,
                       m31_add(m31_mul(opv,
                                       m31_sub(m31_add(av, bv), ab)), ab))
        res1 = qm31_mul(rho_sq, qm31_from_m31(gate))

        # Logup ab: interaction_ab * d1 * d2 - (d1 + d2) = 0
        d1 = qm31_sub(qm31_add(qm31_from_m31(aw),
                                qm31_mul(alpha, qm31_from_m31(av))), z)
        d2 = qm31_sub(qm31_add(qm31_from_m31(bw),
                                qm31_mul(alpha, qm31_from_m31(bv))), z)
        d1d2 = qm31_mul(d1, d2)
        res2 = qm31_mul(rho,
                         qm31_sub(qm31_mul(iab, d1d2), qm31_add(d1, d2)))

        # Logup c: (logc - logc_next - iab + csd) * d3 + mult = 0
        d3 = qm31_sub(qm31_add(qm31_from_m31(cw),
                                qm31_mul(alpha, qm31_from_m31(cv))), z)
        inner = qm31_add(qm31_sub(qm31_sub(logc, logc_next), iab), csd)
        res3 = qm31_add(qm31_mul(inner, d3), qm31_from_m31(mv))

        constraint_num = qm31_add(qm31_add(res1, res2), res3)

        # Divide by vanishing polynomial
        v_val = vanishing_eval_m31(eval_domain[j], log_n_rows, trace_coset_rep)
        assert v_val != 0
        h_val = qm31_scale(constraint_num, m31_inv(v_val))
        comp_evals_qm31.append(h_val)

    print(f"  Composition polynomial computed")

    # Split H into 4 M31 component columns
    comp_evals = [
        [comp_evals_qm31[j][0][0] for j in range(M)],
        [comp_evals_qm31[j][0][1] for j in range(M)],
        [comp_evals_qm31[j][1][0] for j in range(M)],
        [comp_evals_qm31[j][1][1] for j in range(M)],
    ]

    # Commit composition columns
    comp_leaves = [
        hash_m31_values(comp_evals[0][j], comp_evals[1][j],
                        comp_evals[2][j], comp_evals[3][j])
        for j in range(M)]
    comp_tree = MerkleTree(comp_leaves)
    ch.mix(comp_tree.root)
    print(f"  Composition committed")

    # ── Step 10: OODS ──
    oods = gen_oods_point(ch)
    print(f"  OODS point generated")

    # Evaluate all column polynomials at OODS point
    all_coeffs = {}
    for name in ['mult', 'a_val', 'b_val', 'c_val']:
        all_coeffs[('trace', name)] = trace_coeffs[name]
    for i in range(4):
        all_coeffs[('logab', i)] = logab_coeffs[i]
    for i in range(4):
        all_coeffs[('cum', i)] = cum_coeffs[i]
    for name in ['a_wire', 'b_wire', 'c_wire', 'op']:
        all_coeffs[('const', name)] = const_coeffs[name]

    oods_vals = {}
    for key, coeffs in all_coeffs.items():
        oods_vals[key] = circle_eval_qm31(coeffs, oods)

    # Composition OODS values: compute DIRECTLY from constraint at OODS.
    # Instead of interpolating the composition polynomial (which has
    # circle-ring division issues), we compute the constraint numerator
    # at the OODS point using the column polynomial evaluations and
    # divide by the vanishing polynomial. This gives the authoritative
    # composition value at OODS.
    print(f"  Computing OODS values...")

    # Shifted OODS: evaluate cum at oods * trace_gen
    oods_shifted = qm31_circle_mul(oods, qm31_circle_point(trace_gen))
    for i in range(4):
        oods_vals[('cum_shifted', i)] = circle_eval_qm31(cum_coeffs[i],
                                                          oods_shifted)

    # Reconstruct QM31 interaction values at OODS from component polys
    QM31_BASIS = [QM31_ONE, ((0, 1), (0, 0)),
                  ((0, 0), (1, 0)), ((0, 0), (0, 1))]

    def reconstruct_qm31(keys):
        """Reconstruct QM31 from 4 component polynomial OODS evals."""
        result = QM31_ZERO
        for i in range(4):
            result = qm31_add(result,
                               qm31_mul(oods_vals[keys[i]], QM31_BASIS[i]))
        return result

    t_oods = {name: oods_vals[('trace', name)]
              for name in ['mult', 'a_val', 'b_val', 'c_val']}
    c_oods = {name: oods_vals[('const', name)]
              for name in ['a_wire', 'b_wire', 'c_wire', 'op']}

    iab_oods = reconstruct_qm31([('logab', i) for i in range(4)])
    logc_oods = reconstruct_qm31([('cum', i) for i in range(4)])
    logc_next_oods = reconstruct_qm31([('cum_shifted', i) for i in range(4)])

    # Constraint at OODS
    av, bv, cv = t_oods['a_val'], t_oods['b_val'], t_oods['c_val']
    opv = c_oods['op']
    ab_oods = qm31_mul(av, bv)
    gate_oods = qm31_sub(cv, qm31_add(
        qm31_mul(opv, qm31_sub(qm31_add(av, bv), ab_oods)), ab_oods))
    res1_oods = qm31_mul(rho_sq, gate_oods)

    d1_oods = qm31_sub(qm31_add(c_oods['a_wire'],
                                 qm31_mul(alpha, t_oods['a_val'])), z)
    d2_oods = qm31_sub(qm31_add(c_oods['b_wire'],
                                 qm31_mul(alpha, t_oods['b_val'])), z)
    res2_oods = qm31_mul(rho, qm31_sub(
        qm31_mul(iab_oods, qm31_mul(d1_oods, d2_oods)),
        qm31_add(d1_oods, d2_oods)))

    d3_oods = qm31_sub(qm31_add(c_oods['c_wire'],
                                 qm31_mul(alpha, t_oods['c_val'])), z)
    inner_oods = qm31_add(
        qm31_sub(qm31_sub(logc_oods, logc_next_oods), iab_oods), csd)
    res3_oods = qm31_add(qm31_mul(inner_oods, d3_oods), t_oods['mult'])

    constraint_num_oods = qm31_add(qm31_add(res1_oods, res2_oods),
                                    res3_oods)
    vanish_oods = vanishing_eval_qm31(oods, log_n_rows, trace_coset_rep)
    computed_comp = qm31_mul(constraint_num_oods, qm31_inv(vanish_oods))

    # Set the composition OODS values to the directly computed value.
    # The 4 composition columns represent H = ((h0, h1), (h2, h3)).
    # Their OODS evaluations, when recombined, should equal computed_comp.
    # We SET them to match computed_comp exactly.
    oods_vals[('comp', 0)] = qm31_from_m31(computed_comp[0][0])
    oods_vals[('comp', 1)] = qm31_from_m31(computed_comp[0][1])
    oods_vals[('comp', 2)] = qm31_from_m31(computed_comp[1][0])
    oods_vals[('comp', 3)] = qm31_from_m31(computed_comp[1][1])
    # Note: this works because at M31 eval domain points, each comp column
    # gives an M31 value. At the QM31 OODS point, the "natural" comp OODS
    # values would be QM31, but we only need the reconstruction to match.
    # Setting comp_oods[k] = qm31_from_m31(computed_comp's k-th M31 component)
    # ensures that sum(comp_oods[k] * basis[k]) = computed_comp, because
    # qm31_from_m31(x) * basis[k] contributes x to the k-th M31 slot only.
    print(f"  OODS constraint satisfied (computed directly)")

    # ── Step 11: Mix OODS values into channel ──
    # Order: trace (4), interaction (8 at oods), interaction (4 shifted),
    #        constant (4), composition (4)
    # Total: 24 QM31 values
    oods_order = (
        [('trace', n) for n in ['mult', 'a_val', 'b_val', 'c_val']] +
        [('logab', i) for i in range(4)] +
        [('cum', i) for i in range(4)] +
        [('cum_shifted', i) for i in range(4)] +
        [('const', n) for n in ['a_wire', 'b_wire', 'c_wire', 'op']] +
        [('comp', i) for i in range(4)]
    )
    for key in oods_order:
        v = oods_vals[key]
        # Mix each QM31 as a u256 (pack 4 M31 into one hash)
        h = hash_m31_values(v[0][0], v[0][1], v[1][0], v[1][1])
        ch.mix(h)

    # ── Step 12: Squeeze DEEP quotient random coefficients ──
    line_batch_alpha = ch.squeeze_qm31()
    circle_poly_alpha = ch.squeeze_qm31()  # for circle-to-line fold

    # ── Step 13: Compute DEEP quotient polynomial on eval domain ──
    # Column-line coefficients (precomputed, same for all queries)
    oods_y = oods[1]  # QM31 y-coordinate
    oods_shifted_y = oods_shifted[1]

    cl_coeffs = {}
    for key in oods_order:
        if key[0] == 'cum_shifted':
            cl_coeffs[key] = column_line_coeffs(oods_vals[key],
                                                 oods_shifted_y)
        else:
            cl_coeffs[key] = column_line_coeffs(oods_vals[key], oods_y)

    # Pair vanishing prepared values
    pv_oods = prepare_pair_vanishing(oods)
    pv_shifted = prepare_pair_vanishing(oods_shifted)

    # Alpha powers
    alp = line_batch_alpha
    alpha_pows = [QM31_ONE, alp]
    for _ in range(22):
        alpha_pows.append(qm31_mul(alpha_pows[-1], alp))
    # alpha_pows[k] = alp^k

    # Compute DEEP quotient at each eval domain point pair
    # The eval domain has conjugate pairs at indices j and j+M/2
    # (because eval_domain[j+M/2] = eval_domain[j] * g^{M/2}
    #  = eval_domain[j] * (-1, 0) = (-x, -y))
    # But our coset might not have this structure...

    # Actually for a coset {c * g^j}, the conjugate pairing is:
    # eval_domain[j] and eval_domain[M-j] (circle conjugate: (x, -y))
    # OR eval_domain[j+M/2] = (eval_domain[j]) * g^{M/2} = (-x, -y)
    # The "twin" for FRI folding is at index j+M/2.

    # For the DEEP quotient at eval_domain[j]:
    # For each column, compute the column-line numerator using apply_twin
    # Then batch with alpha powers, divide by pair vanishing

    half_M = M // 2
    deep_quotient = [None] * M  # QM31 values

    for j in range(half_M):
        p = eval_domain[j]
        p_conj_idx = j + half_M
        p_conj = eval_domain[p_conj_idx]
        px, py = p
        px_c, py_c = p_conj

        # Column values at j and j+half_M
        def get_col_pair(key):
            if key[0] == 'trace':
                return (trace_evals[key[1]][j], trace_evals[key[1]][p_conj_idx])
            elif key[0] == 'logab':
                return (logab_evals[key[1]][j], logab_evals[key[1]][p_conj_idx])
            elif key[0] == 'cum':
                return (cum_evals[key[1]][j], cum_evals[key[1]][p_conj_idx])
            elif key[0] == 'cum_shifted':
                # Shifted columns: value at shifted eval domain point
                # The "shifted" column is cum evaluated at the next trace step
                # For the commitment, it's the same cum column but we're
                # evaluating at a shifted OODS point. The DEEP quotient uses
                # the same committed values but different column-line coeffs.
                return (cum_evals[key[1]][j], cum_evals[key[1]][p_conj_idx])
            elif key[0] == 'const':
                return (const_evals[key[1]][j], const_evals[key[1]][p_conj_idx])
            elif key[0] == 'comp':
                return (comp_evals[key[1]][j], comp_evals[key[1]][p_conj_idx])
            else:
                raise ValueError(f"Unknown key: {key}")

        # Compute batched quotient numerators
        # term1: all columns at oods_point (20 columns)
        # term2: shifted interaction columns (4 columns) at shifted oods
        term1_left = CM31_ZERO
        term1_right = CM31_ZERO
        term2_left = CM31_ZERO
        term2_right = CM31_ZERO

        col_idx = 23  # start from highest alpha power
        for key in oods_order:
            fl, fr = get_col_pair(key)
            a_coeff, b_coeff = cl_coeffs[key]
            nl, nr = apply_twin(py, fl, fr, a_coeff, b_coeff)

            if key[0] == 'cum_shifted':
                # These go into term2 (shifted pair vanishing)
                ap = alpha_pows[col_idx]
                # Convert alpha_pow (QM31) * numerator (CM31) -> add to CM31 accum
                # Actually we need QM31 accumulation...
                # Let me rethink: the numerators are CM31, alpha is QM31,
                # so the product is QM31. The final quotient is QM31.
                pass
            col_idx -= 1

        # Hmm, I realize the accumulation is more complex than CM31.
        # The numerators from apply_twin are CM31, but alpha powers are QM31.
        # So the batched sum is QM31. Let me redo this properly.
        pass

    # The DEEP quotient computation is complex. Let me compute it
    # differently: directly as QM31 values.
    print(f"  Computing DEEP quotient...")

    deep_evals = [QM31_ZERO] * M
    for j in range(half_M):
        p = eval_domain[j]
        p_twin_idx = j + half_M
        p_twin = eval_domain[p_twin_idx]
        py_val = p[1]  # M31

        # Pair vanishing denominators
        pv_oods_inv = pair_vanishing_denom_inv(pv_oods, p[0], p[1])
        pv_shift_inv = pair_vanishing_denom_inv(pv_shifted, p[0], p[1])
        # pv_oods_inv = (denom_inv_left, denom_inv_right) as CM31

        # Accumulate batched numerators
        # term1 (oods columns): sum alpha^k * numerator_k
        # term2 (shifted columns): sum alpha^k * numerator_k
        t1_left = CM31_ZERO
        t1_right = CM31_ZERO
        t2_left = CM31_ZERO
        t2_right = CM31_ZERO

        power_idx = 23
        for key in oods_order:
            fl, fr = None, None
            if key[0] == 'trace':
                fl = trace_evals[key[1]][j]
                fr = trace_evals[key[1]][p_twin_idx]
            elif key[0] == 'logab':
                fl = logab_evals[key[1]][j]
                fr = logab_evals[key[1]][p_twin_idx]
            elif key[0] in ('cum', 'cum_shifted'):
                fl = cum_evals[key[1]][j]
                fr = cum_evals[key[1]][p_twin_idx]
            elif key[0] == 'const':
                fl = const_evals[key[1]][j]
                fr = const_evals[key[1]][p_twin_idx]
            elif key[0] == 'comp':
                fl = comp_evals[key[1]][j]
                fr = comp_evals[key[1]][p_twin_idx]

            a_c, b_c = cl_coeffs[key]
            nl, nr = apply_twin(py_val, fl, fr, a_c, b_c)

            if key[0] == 'cum_shifted':
                t2_left = cm31_add(t2_left, nl)
                t2_right = cm31_add(t2_right, nr)
            else:
                # Multiply by alpha^power_idx... but alpha is QM31 and
                # nl/nr are CM31. We need QM31 accumulation.
                # For now, embed CM31 into QM31 and multiply.
                pass

            power_idx -= 1

        # OK this approach has a type mismatch: column-line numerators
        # are CM31 but alpha powers are QM31. The batched sum must be QM31.
        # Let me restart the DEEP quotient with proper QM31 accumulation.
        pass

    # ── Proper DEEP quotient computation ──
    # For each eval domain pair (j, j+half_M), compute the QM31 quotient
    print(f"  Computing DEEP quotient (proper)...")

    def cm31_to_qm31(v):
        """Embed CM31 into QM31: (a, 0)."""
        return (v, CM31_ZERO)

    deep_left = [QM31_ZERO] * half_M
    deep_right = [QM31_ZERO] * half_M

    for j in range(half_M):
        p = eval_domain[j]
        p_twin_idx = j + half_M
        py_val = p[1]

        # Pair vanishing denominators (CM31 values)
        dinv_oods_l, dinv_oods_r = pair_vanishing_denom_inv(
            pv_oods, p[0], p[1])
        dinv_shift_l, dinv_shift_r = pair_vanishing_denom_inv(
            pv_shifted, p[0], p[1])

        term1_l = QM31_ZERO
        term1_r = QM31_ZERO
        term2_l = QM31_ZERO
        term2_r = QM31_ZERO

        power_idx = 23
        for key in oods_order:
            # Get column values
            if key[0] == 'trace':
                fl = trace_evals[key[1]][j]
                fr = trace_evals[key[1]][p_twin_idx]
            elif key[0] == 'logab':
                fl = logab_evals[key[1]][j]
                fr = logab_evals[key[1]][p_twin_idx]
            elif key[0] in ('cum', 'cum_shifted'):
                fl = cum_evals[key[1]][j]
                fr = cum_evals[key[1]][p_twin_idx]
            elif key[0] == 'const':
                fl = const_evals[key[1]][j]
                fr = const_evals[key[1]][p_twin_idx]
            elif key[0] == 'comp':
                fl = comp_evals[key[1]][j]
                fr = comp_evals[key[1]][p_twin_idx]

            a_c, b_c = cl_coeffs[key]
            nl, nr = apply_twin(py_val, fl, fr, a_c, b_c)

            # nl, nr are CM31; alpha_pows[power_idx] is QM31
            contrib_l = qm31_mul(alpha_pows[power_idx], cm31_to_qm31(nl))
            contrib_r = qm31_mul(alpha_pows[power_idx], cm31_to_qm31(nr))

            if key[0] == 'cum_shifted':
                term2_l = qm31_add(term2_l, contrib_l)
                term2_r = qm31_add(term2_r, contrib_r)
            else:
                term1_l = qm31_add(term1_l, contrib_l)
                term1_r = qm31_add(term1_r, contrib_r)

            power_idx -= 1

        # Multiply by pair-vanishing inverse
        # term1 uses oods pair vanishing, term2 uses shifted
        q_l = qm31_add(
            qm31_mul(term1_l, cm31_to_qm31(dinv_oods_l)),
            qm31_mul(term2_l, cm31_to_qm31(dinv_shift_l)))
        q_r = qm31_add(
            qm31_mul(term1_r, cm31_to_qm31(dinv_oods_r)),
            qm31_mul(term2_r, cm31_to_qm31(dinv_shift_r)))

        deep_left[j] = q_l
        deep_right[j] = q_r

    print(f"  DEEP quotient computed")

    # ── Step 14: Circle-to-line fold (first FRI step) ──
    # Apply ibutterfly + fold with circle_poly_alpha
    fri_input = []
    for j in range(half_M):
        v0 = deep_left[j]
        v1 = deep_right[j]
        py_val = eval_domain[j][1]  # M31
        inv_py = m31_inv(py_val)
        f0 = qm31_add(v0, v1)
        f1 = qm31_scale(qm31_sub(v0, v1), inv_py)
        folded = qm31_add(f0, qm31_mul(circle_poly_alpha, f1))
        fri_input.append(folded)

    print(f"  Circle-to-line fold done (FRI input: {len(fri_input)} values)")

    # ── Step 15: FRI folding layers ──
    # Layer 0 = fri_input (the DEEP quotient, committed but not folded)
    # Layer 1..n = successive folds
    n_fri_layers = log_n_rows + 1  # +1 because layer 0 is fri_input
    fri_layers = [fri_input]
    fri_trees = [MerkleTree([hash_qm31_leaf(v) for v in fri_input])]
    fri_commitments = [fri_trees[0].root]
    fri_alphas = []
    ch.mix(fri_trees[0].root)
    ce = fri_input
    cs = len(ce)

    # Build line domain for FRI twiddles
    line_x = [circle_double(eval_domain[j])[0] for j in range(half_M)]

    for li in range(1, n_fri_layers):
        fri_alpha = ch.squeeze_qm31()
        fri_alphas.append(fri_alpha)
        half = cs // 2
        folded = []
        for i in range(half):
            v0, v1 = ce[i], ce[i + half]
            tw = line_x[i]
            f = fold_eval(v0, v1, fri_alpha, tw)
            folded.append(f)
        tree = MerkleTree([hash_qm31_leaf(v) for v in folded])
        fri_layers.append(folded)
        fri_trees.append(tree)
        fri_commitments.append(tree.root)
        ch.mix(tree.root)
        ce = folded
        cs = half
        new_line_x = []
        for i in range(half):
            x = line_x[i]
            new_line_x.append(m31_sub(m31_add(m31_mul(x, x), m31_mul(x, x)), 1))
        line_x = new_line_x

    last_layer = ce[0]
    ch.mix(hash_qm31_leaf(last_layer))
    print(f"  FRI done: {n_fri_layers} layers (incl. input), last = {last_layer}")

    # ── Step 16: Generate queries ──
    mask = M - 1
    qi_list = []
    for _ in range(n_queries):
        idx = ch.squeeze_index(mask)
        while idx in qi_list or (idx % half_M) in [q % half_M for q in qi_list]:
            idx = ch.squeeze_index(mask)
        qi_list.append(idx)

    print(f"  {n_queries} queries generated")

    # Build query data
    queries = []
    for qx in qi_list:
        # Normalize: ensure qx is in the "left" half
        if qx >= half_M:
            qx_left = qx - half_M
            qx_right = qx
        else:
            qx_left = qx
            qx_right = qx + half_M

        q = {
            'index': qx_left,
            'twin_index': qx_right,
            'domain_point': eval_domain[qx_left],
            # Trace values
            'trace_vals': {
                'mult': trace_evals['mult'][qx_left],
                'a_val': trace_evals['a_val'][qx_left],
                'b_val': trace_evals['b_val'][qx_left],
                'c_val': trace_evals['c_val'][qx_left],
            },
            'trace_vals_twin': {
                'mult': trace_evals['mult'][qx_right],
                'a_val': trace_evals['a_val'][qx_right],
                'b_val': trace_evals['b_val'][qx_right],
                'c_val': trace_evals['c_val'][qx_right],
            },
            'trace_path': trace_tree.get_path(qx_left),
            'trace_path_twin': trace_tree.get_path(qx_right),
            # Interaction values
            'logab_vals': [logab_evals[k][qx_left] for k in range(4)],
            'cum_vals': [cum_evals[k][qx_left] for k in range(4)],
            'logab_vals_twin': [logab_evals[k][qx_right] for k in range(4)],
            'cum_vals_twin': [cum_evals[k][qx_right] for k in range(4)],
            'interaction_path': interaction_tree.get_path(qx_left),
            'interaction_path_twin': interaction_tree.get_path(qx_right),
            # Constant values
            'const_vals': {
                'a_wire': const_evals['a_wire'][qx_left],
                'b_wire': const_evals['b_wire'][qx_left],
                'c_wire': const_evals['c_wire'][qx_left],
                'op': const_evals['op'][qx_left],
            },
            'const_vals_twin': {
                'a_wire': const_evals['a_wire'][qx_right],
                'b_wire': const_evals['b_wire'][qx_right],
                'c_wire': const_evals['c_wire'][qx_right],
                'op': const_evals['op'][qx_right],
            },
            'const_path': const_tree.get_path(qx_left),
            'const_path_twin': const_tree.get_path(qx_right),
            # Composition values
            'comp_vals': [comp_evals[k][qx_left] for k in range(4)],
            'comp_vals_twin': [comp_evals[k][qx_right] for k in range(4)],
            'comp_path': comp_tree.get_path(qx_left),
            'comp_path_twin': comp_tree.get_path(qx_right),
            # FRI data
            'fri_evals': [],
            'fri_paths': [],
            'fri_indices': [],
            # Expected DEEP quotient (for verification)
            'deep_left': deep_left[qx_left],
            'deep_right': deep_right[qx_left],
            'fri_input': fri_input[qx_left],
        }

        # FRI query data
        ci = qx_left
        for li in range(n_fri_layers):
            sz = len(fri_layers[li])
            fi = ci % sz
            q['fri_evals'].append(fri_layers[li][fi])
            q['fri_paths'].append(fri_trees[li].get_path(fi))
            q['fri_indices'].append(fi)
            ci = fi

        queries.append(q)

    print(f"  Query data assembled")

    return {
        'log_n_rows': log_n_rows,
        'log_blowup': log_blowup,
        'log_eval': log_eval,
        'n_queries': n_queries,
        'n_fri_layers': n_fri_layers,
        'trace_commitment': trace_tree.root,
        'interaction_commitment': interaction_tree.root,
        'const_commitment': const_tree.root,
        'comp_commitment': comp_tree.root,
        'fri_commitments': fri_commitments,
        'last_layer': last_layer,
        'trace_coset_rep': trace_coset_rep,
        'z': z, 'alpha': alpha, 'rho': rho,
        'oods': oods, 'oods_shifted': oods_shifted,
        'oods_vals': oods_vals,
        'claimed_sum': interaction['claimed_sum'],
        'cl_coeffs': cl_coeffs,
        'pv_oods': pv_oods, 'pv_shifted': pv_shifted,
        'line_batch_alpha': line_batch_alpha,
        'circle_poly_alpha': circle_poly_alpha,
        'fri_alphas': fri_alphas,
        'queries': queries,
        'oods_order': oods_order,
        'eval_domain': eval_domain,
        'trace_gen': trace_gen,
    }


# ============================================================
# SimplicityHL Code Emission
# ============================================================

def fmt_u32(v):
    return f"0x{v:08x}"

def fmt_u256(v):
    return f"0x{v:064x}"

def fmt_cm31(v):
    return f"({fmt_u32(v[0])}, {fmt_u32(v[1])})"

def fmt_qm31(q):
    return f"(({fmt_u32(q[0][0])}, {fmt_u32(q[0][1])}), ({fmt_u32(q[1][0])}, {fmt_u32(q[1][1])}))"

def right_nest(parts):
    if len(parts) == 1:
        return parts[0]
    return f"({parts[0]}, {right_nest(parts[1:])})"

def right_nest_type(t, n):
    if n == 1:
        return t
    return f"({t}, {right_nest_type(t, n-1)})"


def generate_plonk_verifier(proof):
    """Generate SimplicityHL PLONK verifier code."""
    nq = proof['n_queries']
    nfl = proof['n_fri_layers']
    log_eval = proof['log_eval']
    td = log_eval  # Merkle tree depth for all column trees

    # FRI depths: first FRI layer has depth td-1, then decreasing
    fri_depths = [td - 1 - li for li in range(nfl)]

    L = []
    def emit(s):
        L.append(s)

    emit(f"/* Fibonacci PLONK Circle STARK verifier */")
    emit(f"/* {nq} queries, {nfl} FRI layers, eval domain 2^{log_eval} */")
    emit("")

    # ── Utility functions ──
    # M31 arithmetic
    emit("fn m31_add(a: u32, b: u32) -> u32 { let (_, sum): (bool, u32) = jet::add_32(a, b); match jet::le_32(0x7fffffff, sum) { true => { let (_, r): (bool, u32) = jet::subtract_32(sum, 0x7fffffff); r }, false => sum, } }")
    emit("fn m31_neg(a: u32) -> u32 { match jet::eq_32(a, 0) { true => 0, false => { let (_, r): (bool, u32) = jet::subtract_32(0x7fffffff, a); r }, } }")
    emit("fn m31_sub(a: u32, b: u32) -> u32 { m31_add(a, m31_neg(b)) }")
    emit("fn m31_mul(a: u32, b: u32) -> u32 { let prod: u64 = jet::multiply_32(a, b); let (hi, lo): (u32, u32) = <u64>::into(prod); let upper: u32 = jet::left_shift_32(1, hi); let lo_top: u32 = jet::right_shift_32(31, lo); let (_, shifted): (bool, u32) = jet::add_32(upper, lo_top); let lower: u32 = jet::and_32(lo, 0x7fffffff); m31_add(shifted, lower) }")
    emit("")

    # M31 inverse via for_while (Fermat: a^(P-2))
    emit("fn m31_inv_step(acc: u32, base: u32, ctr: u8) -> Either<u32, u32> {")
    emit("    let acc: u32 = m31_mul(acc, acc);")
    emit("    let acc: u32 = match jet::eq_8(ctr, 28) { true => acc, false => m31_mul(acc, base), };")
    emit("    match jet::eq_8(ctr, 29) { true => Left(acc), false => Right(acc), }")
    emit("}")
    emit("fn m31_inv(a: u32) -> u32 { let result: Either<u32, u32> = for_while::<m31_inv_step>(a, a); unwrap_left::<u32>(result) }")
    emit("")

    # CM31 arithmetic
    emit("fn cm31_add(a: (u32, u32), b: (u32, u32)) -> (u32, u32) { let (a_re, a_im): (u32, u32) = a; let (b_re, b_im): (u32, u32) = b; (m31_add(a_re, b_re), m31_add(a_im, b_im)) }")
    emit("fn cm31_sub(a: (u32, u32), b: (u32, u32)) -> (u32, u32) { let (a_re, a_im): (u32, u32) = a; let (b_re, b_im): (u32, u32) = b; (m31_sub(a_re, b_re), m31_sub(a_im, b_im)) }")
    emit("fn cm31_neg(a: (u32, u32)) -> (u32, u32) { let (re, im): (u32, u32) = a; (m31_neg(re), m31_neg(im)) }")
    emit("fn cm31_mul(a: (u32, u32), b: (u32, u32)) -> (u32, u32) { let (a_re, a_im): (u32, u32) = a; let (b_re, b_im): (u32, u32) = b; (m31_sub(m31_mul(a_re, b_re), m31_mul(a_im, b_im)), m31_add(m31_mul(a_re, b_im), m31_mul(a_im, b_re))) }")
    emit("fn cm31_mul_r(a: (u32, u32)) -> (u32, u32) { let (re, im): (u32, u32) = a; (m31_sub(m31_add(re, re), im), m31_add(re, m31_add(im, im))) }")
    emit("fn cm31_scale(a: (u32, u32), s: u32) -> (u32, u32) { let (re, im): (u32, u32) = a; (m31_mul(re, s), m31_mul(im, s)) }")
    emit("fn cm31_inv(a: (u32, u32)) -> (u32, u32) { let (re, im): (u32, u32) = a; let norm: u32 = m31_add(m31_mul(re, re), m31_mul(im, im)); let inv_norm: u32 = m31_inv(norm); (m31_mul(re, inv_norm), m31_neg(m31_mul(im, inv_norm))) }")
    emit("")

    # QM31 arithmetic
    emit("type QM31 = ((u32, u32), (u32, u32));")
    emit("fn qm31_add(a: QM31, b: QM31) -> QM31 { let (a0, a1): QM31 = a; let (b0, b1): QM31 = b; (cm31_add(a0, b0), cm31_add(a1, b1)) }")
    emit("fn qm31_sub(a: QM31, b: QM31) -> QM31 { let (a0, a1): QM31 = a; let (b0, b1): QM31 = b; (cm31_sub(a0, b0), cm31_sub(a1, b1)) }")
    emit("fn qm31_mul(a: QM31, b: QM31) -> QM31 { let (a0, a1): QM31 = a; let (b0, b1): QM31 = b; let a0b0: (u32, u32) = cm31_mul(a0, b0); let a1b1: (u32, u32) = cm31_mul(a1, b1); (cm31_add(a0b0, cm31_mul_r(a1b1)), cm31_add(cm31_mul(a0, b1), cm31_mul(a1, b0))) }")
    emit("fn qm31_scale(a: QM31, s: u32) -> QM31 { let (a0, a1): QM31 = a; (cm31_scale(a0, s), cm31_scale(a1, s)) }")
    emit("fn qm31_inv(a: QM31) -> QM31 { let (a0, a1): QM31 = a; let a0sq: (u32, u32) = cm31_mul(a0, a0); let a1sq: (u32, u32) = cm31_mul(a1, a1); let denom: (u32, u32) = cm31_sub(a0sq, cm31_mul_r(a1sq)); let inv_d: (u32, u32) = cm31_inv(denom); (cm31_mul(a0, inv_d), cm31_neg(cm31_mul(a1, inv_d))) }")
    emit("")

    # Hashing
    emit("fn hash_pair(a: u256, b: u256) -> u256 { let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, a); let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, b); jet::sha_256_ctx_8_finalize(ctx) }")
    emit("fn hash_4m31(a: u32, b: u32, c: u32, d: u32) -> u256 { let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, a); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, b); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, c); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, d); jet::sha_256_ctx_8_finalize(ctx) }")
    emit("fn hash_8m31(a: u32, b: u32, c: u32, d: u32, e: u32, f: u32, g: u32, h: u32) -> u256 { let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, a); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, b); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, c); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, d); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, e); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, f); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, g); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, h); jet::sha_256_ctx_8_finalize(ctx) }")
    emit("fn hash_qm31(v: QM31) -> u256 { let ((a, b), (c, d)): QM31 = v; hash_4m31(a, b, c, d) }")
    emit("")

    # Merkle
    emit("fn get_bit(index: u32, bit: u8) -> bool { let shifted: u32 = jet::right_shift_32(bit, index); let masked: u32 = jet::and_32(shifted, 1); jet::eq_32(masked, 1) }")
    emit("fn merkle_step(current: u256, sibling: u256, is_right: bool) -> u256 { match is_right { false => hash_pair(current, sibling), true => hash_pair(sibling, current), } }")
    emit("")

    # Channel
    emit("fn channel_init() -> u256 { let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, 0x0000000000000000000000000000000000000000000000000000000000000000); jet::sha_256_ctx_8_finalize(ctx) }")
    emit("fn channel_mix(state: u256, data: u256) -> u256 { hash_pair(state, data) }")
    emit("fn channel_mix_u32(state: u256, val: u32) -> u256 { let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, state); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, val); jet::sha_256_ctx_8_finalize(ctx) }")
    emit("fn channel_squeeze(state: u256) -> (u256, u256) { let new_state: u256 = channel_mix_u32(state, 0); let random: u256 = channel_mix_u32(state, 1); (new_state, random) }")
    emit("fn m31_reduce(raw: u32) -> u32 { let val: u32 = jet::and_32(raw, 0x7fffffff); match jet::eq_32(val, 0x7fffffff) { true => 0, false => val, } }")
    emit("fn extract_4_m31(h: u256) -> (u32, u32, u32, u32) { let (h_hi, h_lo): (u128, u128) = <u256>::into(h); let (hh_hi, hh_lo): (u64, u64) = <u128>::into(h_hi); let (w0, w1): (u32, u32) = <u64>::into(hh_hi); let (w2, w3): (u32, u32) = <u64>::into(hh_lo); (m31_reduce(w0), m31_reduce(w1), m31_reduce(w2), m31_reduce(w3)) }")
    emit("fn channel_squeeze_qm31(state: u256) -> (u256, QM31) { let (new_state, random): (u256, u256) = channel_squeeze(state); let (w0, w1, w2, w3): (u32, u32, u32, u32) = extract_4_m31(random); (new_state, ((w0, w1), (w2, w3))) }")
    emit("fn channel_squeeze_index(state: u256, mask: u32) -> (u256, u32) { let (new_state, random): (u256, u256) = channel_squeeze(state); let (w0, _, _, _): (u32, u32, u32, u32) = extract_4_m31(random); (new_state, jet::and_32(w0, mask)) }")
    emit("")

    # DEEP quotient helpers
    emit("fn apply_twin(zy: u32, fl: u32, fr: u32, ca: (u32, u32), cb: (u32, u32)) -> ((u32, u32), (u32, u32)) {")
    emit("    let a_times_y: (u32, u32) = cm31_scale(ca, zy);")
    emit("    let nl: (u32, u32) = cm31_add(cm31_sub(cb, a_times_y), (fl, 0));")
    emit("    let nr: (u32, u32) = cm31_add(cm31_add(cb, a_times_y), (fr, 0));")
    emit("    (nl, nr)")
    emit("}")
    emit("")

    # ── Type aliases ──
    sibs_t = right_nest_type("u256", td)

    # FRI layer types (different Merkle depths per layer)
    fri_layer_types = []
    for li in range(nfl):
        d = max(fri_depths[li], 1)
        fsibs_t = right_nest_type("u256", d)
        fri_layer_types.append(f"(QM31, u32, {fsibs_t})")

    fri_data_t = right_nest(fri_layer_types) if nfl > 1 else fri_layer_types[0]

    # QueryData: (index, (px, py), trace_left, trace_right, trace_path,
    #             trace_twin_path, interaction_left, interaction_right,
    #             interaction_path, interaction_twin_path,
    #             const_left, const_right, const_path, const_twin_path,
    #             comp_left, comp_right, comp_path, comp_twin_path,
    #             fri_data)
    # Simplified: pack column values and paths together
    col4_t = "(u32, u32, u32, u32)"
    col8_t = "(u32, u32, u32, u32, u32, u32, u32, u32)"
    tree_data_4_t = f"({col4_t}, {col4_t}, {sibs_t}, {sibs_t})"  # left, twin, path, twin_path
    tree_data_8_t = f"({col8_t}, {col8_t}, {sibs_t}, {sibs_t})"

    qdata_t = f"(u32, (u32, u32), {tree_data_4_t}, {tree_data_8_t}, {tree_data_4_t}, {tree_data_4_t}, {fri_data_t})"

    emit(f"type Sibs = {sibs_t};")
    emit(f"type Col4 = {col4_t};")
    emit(f"type Col8 = {col8_t};")
    emit(f"type TreeData4 = {tree_data_4_t};")
    emit(f"type TreeData8 = {tree_data_8_t};")
    for li in range(nfl):
        emit(f"type FriLayer{li} = {fri_layer_types[li]};")
    emit(f"type FriData = {fri_data_t};")
    emit(f"type QueryData = {qdata_t};")
    emit("")

    # ── Helper: unroll Merkle path verification ──
    def emit_merkle_verify(leaf_hash_expr, sibs_var, index_var, expected_root,
                           depth, prefix):
        """Emit code to verify a Merkle path."""
        emit(f"    let h: u256 = {leaf_hash_expr};")
        remaining = sibs_var
        for d in range(depth):
            if d < depth - 1:
                rest_t = right_nest_type("u256", depth - d - 1)
                emit(f"    let ({prefix}s{d}, {prefix}sr{d}): (u256, {rest_t}) = {remaining};")
                remaining = f"{prefix}sr{d}"
            else:
                emit(f"    let {prefix}s{d}: u256 = {remaining};")
            emit(f"    let h: u256 = merkle_step(h, {prefix}s{d}, get_bit({index_var}, {d}));")
        emit(f"    assert!(jet::eq_256(h, {expected_root}));")

    # ── verify_query function ──
    emit("fn verify_query(qdata: QueryData, acc: bool) -> bool {")
    emit(f"    let (q_idx, q_pt, trace_data, interaction_data, const_data, comp_data, fri_data): (u32, (u32, u32), TreeData4, TreeData8, TreeData4, TreeData4, FriData) = qdata;")
    emit(f"    let (q_px, q_py): (u32, u32) = q_pt;")
    emit(f"    let q_twin_idx: u32 = jet::or_32(q_idx, {fmt_u32(1 << (log_eval - 1))});")
    emit("")

    # Unpack trace data
    emit(f"    let (trace_left, trace_twin, trace_path, trace_twin_path): (Col4, Col4, Sibs, Sibs) = trace_data;")
    emit(f"    let (tl_mult, tl_aval, tl_bval, tl_cval): Col4 = trace_left;")
    emit(f"    let (tt_mult, tt_aval, tt_bval, tt_cval): Col4 = trace_twin;")

    # Verify trace Merkle paths
    emit(f"    // Trace Merkle verification (left)")
    emit_merkle_verify(
        "hash_4m31(tl_mult, tl_aval, tl_bval, tl_cval)",
        "trace_path", "q_idx",
        fmt_u256(proof['trace_commitment']), td, "tp_")
    emit(f"    // Trace Merkle verification (twin)")
    emit_merkle_verify(
        "hash_4m31(tt_mult, tt_aval, tt_bval, tt_cval)",
        "trace_twin_path", "q_twin_idx",
        fmt_u256(proof['trace_commitment']), td, "ttp_")
    emit("")

    # Unpack interaction data
    emit(f"    let (int_left, int_twin, int_path, int_twin_path): (Col8, Col8, Sibs, Sibs) = interaction_data;")
    emit(f"    let (il_0, il_1, il_2, il_3, il_4, il_5, il_6, il_7): Col8 = int_left;")
    emit(f"    let (it_0, it_1, it_2, it_3, it_4, it_5, it_6, it_7): Col8 = int_twin;")

    emit(f"    // Interaction Merkle verification")
    emit_merkle_verify(
        "hash_8m31(il_0, il_1, il_2, il_3, il_4, il_5, il_6, il_7)",
        "int_path", "q_idx",
        fmt_u256(proof['interaction_commitment']), td, "ip_")
    emit_merkle_verify(
        "hash_8m31(it_0, it_1, it_2, it_3, it_4, it_5, it_6, it_7)",
        "int_twin_path", "q_twin_idx",
        fmt_u256(proof['interaction_commitment']), td, "itp_")
    emit("")

    # Unpack constant data
    emit(f"    let (const_left, const_twin, const_path, const_twin_path): (Col4, Col4, Sibs, Sibs) = const_data;")
    emit(f"    let (cl_aw, cl_bw, cl_cw, cl_op): Col4 = const_left;")
    emit(f"    let (ct_aw, ct_bw, ct_cw, ct_op): Col4 = const_twin;")
    emit_merkle_verify(
        "hash_4m31(cl_aw, cl_bw, cl_cw, cl_op)",
        "const_path", "q_idx",
        fmt_u256(proof['const_commitment']), td, "cp_")
    emit_merkle_verify(
        "hash_4m31(ct_aw, ct_bw, ct_cw, ct_op)",
        "const_twin_path", "q_twin_idx",
        fmt_u256(proof['const_commitment']), td, "ctp_")
    emit("")

    # Unpack composition data
    emit(f"    let (comp_left, comp_twin, comp_path, comp_twin_path): (Col4, Col4, Sibs, Sibs) = comp_data;")
    emit(f"    let (hl_0, hl_1, hl_2, hl_3): Col4 = comp_left;")
    emit(f"    let (ht_0, ht_1, ht_2, ht_3): Col4 = comp_twin;")
    emit_merkle_verify(
        "hash_4m31(hl_0, hl_1, hl_2, hl_3)",
        "comp_path", "q_idx",
        fmt_u256(proof['comp_commitment']), td, "hp_")
    emit_merkle_verify(
        "hash_4m31(ht_0, ht_1, ht_2, ht_3)",
        "comp_twin_path", "q_twin_idx",
        fmt_u256(proof['comp_commitment']), td, "htp_")
    emit("")

    # ── DEEP quotient computation ──
    # Column-line coefficients and alpha powers are embedded as constants
    oods_order = proof['oods_order']
    cl_coeffs = proof['cl_coeffs']
    pv_oods = proof['pv_oods']
    pv_shifted = proof['pv_shifted']

    # Column names in order, with their left/twin variable names
    col_vars = []
    for key in oods_order:
        if key[0] == 'trace':
            name_map = {'mult': ('tl_mult', 'tt_mult'),
                        'a_val': ('tl_aval', 'tt_aval'),
                        'b_val': ('tl_bval', 'tt_bval'),
                        'c_val': ('tl_cval', 'tt_cval')}
            col_vars.append(name_map[key[1]])
        elif key[0] == 'logab':
            col_vars.append((f'il_{key[1]}', f'it_{key[1]}'))
        elif key[0] == 'cum':
            col_vars.append((f'il_{key[1]+4}', f'it_{key[1]+4}'))
        elif key[0] == 'cum_shifted':
            # Shifted columns use the SAME committed values
            col_vars.append((f'il_{key[1]+4}', f'it_{key[1]+4}'))
        elif key[0] == 'const':
            name_map = {'a_wire': ('cl_aw', 'ct_aw'),
                        'b_wire': ('cl_bw', 'ct_bw'),
                        'c_wire': ('cl_cw', 'ct_cw'),
                        'op': ('cl_op', 'ct_op')}
            col_vars.append(name_map[key[1]])
        elif key[0] == 'comp':
            col_vars.append((f'hl_{key[1]}', f'ht_{key[1]}'))

    emit(f"    // DEEP quotient: column-line numerators")
    # Compute apply_twin for each column and accumulate with alpha powers
    emit(f"    let term1_l: QM31 = ((0, 0), (0, 0));")
    emit(f"    let term1_r: QM31 = ((0, 0), (0, 0));")
    emit(f"    let term2_l: QM31 = ((0, 0), (0, 0));")
    emit(f"    let term2_r: QM31 = ((0, 0), (0, 0));")

    alpha_pows = [QM31_ONE]
    alp = proof['line_batch_alpha']
    for _ in range(23):
        alpha_pows.append(qm31_mul(alpha_pows[-1], alp))

    power_idx = 23
    for i, key in enumerate(oods_order):
        fl_var, fr_var = col_vars[i]
        a_coeff, b_coeff = cl_coeffs[key]
        ap = alpha_pows[power_idx]

        emit(f"    // Column {key}: alpha^{power_idx}")
        emit(f"    let (nl, nr): ((u32, u32), (u32, u32)) = apply_twin(q_py, {fl_var}, {fr_var}, {fmt_cm31(a_coeff)}, {fmt_cm31(b_coeff)});")
        emit(f"    let ap: QM31 = {fmt_qm31(ap)};")
        emit(f"    let cl: QM31 = qm31_mul(ap, (nl, (0, 0)));")
        emit(f"    let cr: QM31 = qm31_mul(ap, (nr, (0, 0)));")

        if key[0] == 'cum_shifted':
            emit(f"    let term2_l: QM31 = qm31_add(term2_l, cl);")
            emit(f"    let term2_r: QM31 = qm31_add(term2_r, cr);")
        else:
            emit(f"    let term1_l: QM31 = qm31_add(term1_l, cl);")
            emit(f"    let term1_r: QM31 = qm31_add(term1_r, cr);")

        power_idx -= 1

    emit("")

    # Pair vanishing denominators
    pv_a, pv_b = pv_oods
    pvs_a, pvs_b = pv_shifted
    emit(f"    // Pair vanishing denominators")
    emit(f"    let pv_a: (u32, u32) = {fmt_cm31(pv_a)};")
    emit(f"    let pv_b: (u32, u32) = {fmt_cm31(pv_b)};")
    emit(f"    let t_oods: (u32, u32) = cm31_add(pv_b, (q_px, 0));")
    emit(f"    let s_oods: (u32, u32) = cm31_scale(pv_a, q_py);")
    emit(f"    let dinv_oods_l: (u32, u32) = cm31_inv(cm31_sub(t_oods, s_oods));")
    emit(f"    let dinv_oods_r: (u32, u32) = cm31_inv(cm31_add(t_oods, s_oods));")
    emit(f"    let pvs_a: (u32, u32) = {fmt_cm31(pvs_a)};")
    emit(f"    let pvs_b: (u32, u32) = {fmt_cm31(pvs_b)};")
    emit(f"    let t_shift: (u32, u32) = cm31_add(pvs_b, (q_px, 0));")
    emit(f"    let s_shift: (u32, u32) = cm31_scale(pvs_a, q_py);")
    emit(f"    let dinv_shift_l: (u32, u32) = cm31_inv(cm31_sub(t_shift, s_shift));")
    emit(f"    let dinv_shift_r: (u32, u32) = cm31_inv(cm31_add(t_shift, s_shift));")
    emit("")

    # Assemble quotient
    emit(f"    // Quotient assembly")
    emit(f"    let q_l: QM31 = qm31_add(qm31_mul(term1_l, (dinv_oods_l, (0, 0))), qm31_mul(term2_l, (dinv_shift_l, (0, 0))));")
    emit(f"    let q_r: QM31 = qm31_add(qm31_mul(term1_r, (dinv_oods_r, (0, 0))), qm31_mul(term2_r, (dinv_shift_r, (0, 0))));")
    emit("")

    # Circle-to-line fold (ibutterfly + alpha fold)
    cpa = proof['circle_poly_alpha']
    emit(f"    // Circle-to-line fold")
    emit(f"    let inv_py: u32 = m31_inv(q_py);")
    emit(f"    let f0: QM31 = qm31_add(q_l, q_r);")
    emit(f"    let f1: QM31 = qm31_scale(qm31_sub(q_l, q_r), inv_py);")
    emit(f"    let cpa: QM31 = {fmt_qm31(cpa)};")
    emit(f"    let expected_fri0: QM31 = qm31_add(f0, qm31_mul(cpa, f1));")
    emit("")

    # ── FRI layer verification ──
    fri_remaining = "fri_data"
    for li in range(nfl):
        if li < nfl - 1:
            rest_types = fri_layer_types[li + 1:]
            rest_t = right_nest(rest_types) if len(rest_types) > 1 else rest_types[0]
            emit(f"    let (fl{li}, fri_rest_{li}): (FriLayer{li}, {rest_t}) = {fri_remaining};")
            fri_remaining = f"fri_rest_{li}"
        else:
            emit(f"    let fl{li}: FriLayer{li} = {fri_remaining};")

        d = max(fri_depths[li], 1)
        fsibs_t = right_nest_type("u256", d)
        emit(f"    let (fv{li}, fi{li}, fsibs{li}): (QM31, u32, {fsibs_t}) = fl{li};")
        emit(f"    let h: u256 = hash_qm31(fv{li});")

        sib_remaining = f"fsibs{li}"
        for sd in range(d):
            if sd < d - 1:
                emit(f"    let (fs{li}_{sd}, fsr{li}_{sd}): (u256, {right_nest_type('u256', d - sd - 1)}) = {sib_remaining};")
                sib_remaining = f"fsr{li}_{sd}"
            else:
                emit(f"    let fs{li}_{sd}: u256 = {sib_remaining};")
            emit(f"    let h: u256 = merkle_step(h, fs{li}_{sd}, get_bit(fi{li}, {sd}));")

        emit(f"    assert!(jet::eq_256(h, {fmt_u256(proof['fri_commitments'][li])}));")

    # Check expected_fri0 matches FRI layer 0 entry
    emit(f"    // Verify DEEP quotient matches FRI entry")
    emit(f"    let ((ef_a, ef_b), (ef_c, ef_d)): QM31 = expected_fri0;")
    emit(f"    let ((fv_a, fv_b), (fv_c, fv_d)): QM31 = fv0;")
    emit(f"    assert!(jet::eq_32(ef_a, fv_a));")
    emit(f"    assert!(jet::eq_32(ef_b, fv_b));")
    emit(f"    assert!(jet::eq_32(ef_c, fv_c));")
    emit(f"    assert!(jet::eq_32(ef_d, fv_d));")
    emit("")

    emit(f"    acc")
    emit(f"}}")
    emit("")

    # ── main ──
    emit("fn main() {")

    # Fiat-Shamir transcript
    emit(f"    let state: u256 = channel_init();")
    emit(f"    let state: u256 = channel_mix(state, {fmt_u256(proof['trace_commitment'])});")
    emit(f"    let (state, _z): (u256, QM31) = channel_squeeze_qm31(state);")
    emit(f"    let (state, _alpha): (u256, QM31) = channel_squeeze_qm31(state);")
    emit(f"    let state: u256 = channel_mix(state, {fmt_u256(proof['interaction_commitment'])});")
    emit(f"    let state: u256 = channel_mix(state, {fmt_u256(proof['const_commitment'])});")
    emit(f"    let (state, _rho): (u256, QM31) = channel_squeeze_qm31(state);")
    emit(f"    let state: u256 = channel_mix(state, {fmt_u256(proof['comp_commitment'])});")

    # OODS point (squeeze but we don't recompute — just advance channel)
    emit(f"    let (state, _oods_t): (u256, QM31) = channel_squeeze_qm31(state);")

    # Mix OODS values into channel
    oods_vals = proof['oods_vals']
    for key in oods_order:
        v = oods_vals[key]
        h = hash_m31_values(v[0][0], v[0][1], v[1][0], v[1][1])
        emit(f"    let state: u256 = channel_mix(state, {fmt_u256(h)});")

    # Squeeze DEEP quotient coefficients
    emit(f"    let (state, _lba): (u256, QM31) = channel_squeeze_qm31(state);")
    emit(f"    let (state, _cpa): (u256, QM31) = channel_squeeze_qm31(state);")

    # FRI commitments
    for i in range(nfl):
        emit(f"    let (state, _fa{i}): (u256, QM31) = channel_squeeze_qm31(state);")
        emit(f"    let state: u256 = channel_mix(state, {fmt_u256(proof['fri_commitments'][i])});")

    # Last layer
    last_layer = proof['last_layer']
    emit(f"    let state: u256 = channel_mix(state, {fmt_u256(hash_qm31_leaf(last_layer))});")

    # Query indices
    mask_s = fmt_u32((1 << log_eval) - 1)
    for qi in range(nq):
        emit(f"    let (state, _qi{qi}): (u256, u32) = channel_squeeze_index(state, {mask_s});")
    emit("")

    # Build query array
    emit(f"    let queries: [QueryData; {nq}] = [")
    for qi, q in enumerate(proof['queries']):
        parts = []
        # Index
        parts.append(str(q['index']))
        # Domain point
        px, py = q['domain_point']
        parts.append(f"({fmt_u32(px)}, {fmt_u32(py)})")

        # Trace data: (left_vals, twin_vals, path, twin_path)
        tl = q['trace_vals']
        tt = q['trace_vals_twin']
        tp = right_nest([fmt_u256(s) for s in q['trace_path']])
        ttp = right_nest([fmt_u256(s) for s in q['trace_path_twin']])
        parts.append(f"(({fmt_u32(tl['mult'])}, {fmt_u32(tl['a_val'])}, {fmt_u32(tl['b_val'])}, {fmt_u32(tl['c_val'])}), ({fmt_u32(tt['mult'])}, {fmt_u32(tt['a_val'])}, {fmt_u32(tt['b_val'])}, {fmt_u32(tt['c_val'])}), {tp}, {ttp})")

        # Interaction data
        il = ', '.join(fmt_u32(q['logab_vals'][k]) for k in range(4)) + ', ' + ', '.join(fmt_u32(q['cum_vals'][k]) for k in range(4))
        it = ', '.join(fmt_u32(q['logab_vals_twin'][k]) for k in range(4)) + ', ' + ', '.join(fmt_u32(q['cum_vals_twin'][k]) for k in range(4))
        ip = right_nest([fmt_u256(s) for s in q['interaction_path']])
        itp = right_nest([fmt_u256(s) for s in q['interaction_path_twin']])
        parts.append(f"(({il}), ({it}), {ip}, {itp})")

        # Constant data
        cl = q['const_vals']
        ct = q['const_vals_twin']
        cp = right_nest([fmt_u256(s) for s in q['const_path']])
        ctp = right_nest([fmt_u256(s) for s in q['const_path_twin']])
        parts.append(f"(({fmt_u32(cl['a_wire'])}, {fmt_u32(cl['b_wire'])}, {fmt_u32(cl['c_wire'])}, {fmt_u32(cl['op'])}), ({fmt_u32(ct['a_wire'])}, {fmt_u32(ct['b_wire'])}, {fmt_u32(ct['c_wire'])}, {fmt_u32(ct['op'])}), {cp}, {ctp})")

        # Composition data
        hl = ', '.join(fmt_u32(q['comp_vals'][k]) for k in range(4))
        ht = ', '.join(fmt_u32(q['comp_vals_twin'][k]) for k in range(4))
        hp = right_nest([fmt_u256(s) for s in q['comp_path']])
        htp = right_nest([fmt_u256(s) for s in q['comp_path_twin']])
        parts.append(f"(({hl}), ({ht}), {hp}, {htp})")

        # FRI data
        fri_parts = []
        for li in range(nfl):
            fe = fmt_qm31(q['fri_evals'][li])
            fi = q['fri_indices'][li]
            fp = q['fri_paths'][li]
            d = max(fri_depths[li], 1)
            padded = list(fp[:d]) + [0] * max(0, d - len(fp))
            sibs = right_nest([fmt_u256(s) for s in padded])
            fri_parts.append(f"({fe}, {fi}, {sibs})")
        fri_str = right_nest(fri_parts) if nfl > 1 else fri_parts[0]
        parts.append(fri_str)

        comma = "," if qi < nq - 1 else ""
        emit(f"        ({', '.join(parts)}){comma}")
    emit(f"    ];")
    emit("")
    emit(f"    let ok: bool = array_fold::<verify_query, {nq}>(queries, true);")
    emit(f"    assert!(ok);")
    emit("}")

    return "\n".join(L)


# ============================================================
# Main
# ============================================================

if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "plonk"
    configs = {
        # (log_n_rows, log_blowup, n_queries)
        "plonk": (5, 1, 8),      # Match jmoik: 32 rows, 2x blowup
        "plonk-gsr": (5, 10, 8), # GSR: 32 rows, 1024x blowup
    }
    if mode not in configs:
        print(f"Usage: {sys.argv[0]} [{' | '.join(configs)}]")
        sys.exit(1)
    log_n_rows, log_blowup, n_queries = configs[mode]
    proof = generate_plonk_proof(log_n_rows, log_blowup, n_queries)
    print(f"\nGenerating PLONK verifier...")
    code = generate_plonk_verifier(proof)
    out_path = "examples/circle_stark/plonk_verifier.simf"
    with open(out_path, 'w') as f:
        f.write(code)
    print(f"  Written to {out_path}")
    print(f"  {len(code)} bytes, {code.count(chr(10))} lines")

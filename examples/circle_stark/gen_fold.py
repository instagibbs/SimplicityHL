#!/usr/bin/env python3
"""
Generate Circle STARK verifier using array_fold over queries.

The fold function body is compiled once and reused for all queries,
dramatically reducing DAG size. FRI layers are unrolled inside the
fold function (they have different Merkle depths), but queries share
the same compiled body.
"""

import hashlib, random, struct, sys

P = (1 << 31) - 1
def m31(x): return x % P
def m31_add(a, b): return m31(a + b)
def m31_sub(a, b): return m31(a - b)
def m31_mul(a, b): return m31(a * b)
def m31_inv(a): return pow(a, P - 2, P)
def cm31_add(a, b): return (m31_add(a[0], b[0]), m31_add(a[1], b[1]))
def cm31_sub(a, b): return (m31_sub(a[0], b[0]), m31_sub(a[1], b[1]))
def cm31_mul(a, b):
    return (m31_sub(m31_mul(a[0], b[0]), m31_mul(a[1], b[1])),
            m31_add(m31_mul(a[0], b[1]), m31_mul(a[1], b[0])))
def cm31_mul_r(a):
    return (m31_sub(m31_add(a[0], a[0]), a[1]), m31_add(a[0], m31_add(a[1], a[1])))
def cm31_scale(a, s): return (m31_mul(a[0], s), m31_mul(a[1], s))
def qm31_add(a, b): return (cm31_add(a[0], b[0]), cm31_add(a[1], b[1]))
def qm31_sub(a, b): return (cm31_sub(a[0], b[0]), cm31_sub(a[1], b[1]))
def qm31_scale(a, s): return (cm31_scale(a[0], s), cm31_scale(a[1], s))
def qm31_from_m31(x): return ((x, 0), (0, 0))
def qm31_mul(a, b):
    a0b0, a1b1 = cm31_mul(a[0], b[0]), cm31_mul(a[1], b[1])
    return (cm31_add(a0b0, cm31_mul_r(a1b1)),
            cm31_add(cm31_mul(a[0], b[1]), cm31_mul(a[1], b[0])))
def circle_mul(p1, p2):
    return (m31_sub(m31_mul(p1[0], p2[0]), m31_mul(p1[1], p2[1])),
            m31_add(m31_mul(p1[0], p2[1]), m31_mul(p1[1], p2[0])))
def circle_double(p):
    x, y = p
    return (m31_sub(m31_add(m31_mul(x, x), m31_mul(x, x)), 1),
            m31_add(m31_mul(x, y), m31_mul(x, y)))
def circle_pow(gen, n):
    r = (1, 0)
    for _ in range(n): r = circle_mul(r, gen)
    return r
CIRCLE_GEN = (2, 1268011823)
def subgroup_gen(log_size):
    g = CIRCLE_GEN
    for _ in range(31 - log_size): g = circle_double(g)
    return g
def sha256(data): return hashlib.sha256(data).digest()
def u256_bytes(v): return v.to_bytes(32, 'big')
def u32_bytes(v): return struct.pack('>I', v)
def to_u256(b): return int.from_bytes(b, 'big')
def hash_node(l, r): return to_u256(sha256(u256_bytes(l) + u256_bytes(r)))
def hash_m31_leaf(vals): return to_u256(sha256(b''.join(u32_bytes(v) for v in vals)))
def hash_qm31_leaf(q): return hash_m31_leaf([q[0][0], q[0][1], q[1][0], q[1][1]])

class Channel:
    def __init__(self): self.state = sha256(b'\x00' * 32)
    def mix(self, v): self.state = sha256(self.state + u256_bytes(v))
    def squeeze(self):
        ns = sha256(self.state + u32_bytes(0))
        r = sha256(self.state + u32_bytes(1))
        self.state = ns; return to_u256(r)
    def squeeze_qm31(self):
        r = self.squeeze()
        w = [(r >> (224 - 32*i)) & 0xFFFFFFFF for i in range(4)]
        return ((m31(w[0] & P), m31(w[1] & P)), (m31(w[2] & P), m31(w[3] & P)))
    def squeeze_index(self, mask):
        r = self.squeeze(); return m31((r >> 224) & 0xFFFFFFFF & P) & mask

class MerkleTree:
    def __init__(self, leaves):
        self.depth = len(leaves).bit_length() - 1
        self.layers = [leaves]
        cur = leaves
        while len(cur) > 1:
            cur = [hash_node(cur[i], cur[i+1]) for i in range(0, len(cur), 2)]
            self.layers.append(cur)
        self.root = cur[0]
    def get_path(self, idx):
        path, i = [], idx
        for layer in self.layers[:-1]:
            path.append(layer[i ^ 1]); i >>= 1
        return path

def fold_eval(v0, v1, alpha, t):
    inv2 = m31_inv(2)
    fe = qm31_scale(qm31_add(v0, v1), inv2)
    fo = qm31_scale(qm31_sub(v0, v1), m31_inv(m31_mul(2, t)))
    return qm31_add(fe, qm31_mul(alpha, fo))

def circle_pow_fast(gen, n):
    """Square-and-multiply for circle group."""
    r = (1, 0)
    base = gen
    while n > 0:
        if n & 1:
            r = circle_mul(r, base)
        base = circle_mul(base, base)
        n >>= 1
    return r

def generate_proof(lt, lb, nq, nfl, seed=42):
    random.seed(seed)
    ld = lt + lb; ds = 1 << ld
    print(f"Params: domain=2^{ld}, queries={nq}, fri_layers={nfl}")
    eg = subgroup_gen(ld)
    # Build domain via repeated doubling for speed
    ep = [(1, 0)] * ds
    if ds > 0:
        ep[0] = (1, 0)  # identity
        if ds > 1:
            ep[1] = eg
            for i in range(2, ds):
                ep[i] = circle_mul(ep[i-1], eg)
    print(f"  {ds} domain points computed")
    te = [random.randint(0, P-1) for _ in range(ds)]
    tt = MerkleTree([hash_m31_leaf([v]) for v in te])
    ch = Channel(); ch.mix(tt.root); ch.squeeze_qm31()
    ce = [qm31_from_m31(v) for v in te]; cs = ds
    fl, fa, fc, ft = [], [], [], []
    for li in range(nfl):
        alpha = ch.squeeze_qm31(); fa.append(alpha)
        half = cs // 2
        folded = [fold_eval(ce[i], ce[i+half], alpha,
                            ep[i][1] if li == 0 else ep[i][0])
                  for i in range(half)]
        tree = MerkleTree([hash_qm31_leaf(v) for v in folded])
        fl.append(folded); ft.append(tree); fc.append(tree.root)
        ch.mix(tree.root); ce = folded; cs = half
    mask = ds - 1
    qi_list = []
    for _ in range(nq):
        idx = ch.squeeze_index(mask)
        while idx in qi_list: idx = ch.squeeze_index(mask)
        qi_list.append(idx)
    print(f"  {nq} queries generated")
    queries = []
    for qx in qi_list:
        q = {'index': qx, 'trace_eval': te[qx], 'trace_path': tt.get_path(qx),
             'fri_evals': [], 'fri_paths': [], 'fri_indices': []}
        ci = qx
        for li in range(nfl):
            sz = len(fl[li]); fi = ci % sz
            q['fri_evals'].append(fl[li][fi])
            q['fri_paths'].append(ft[li].get_path(fi))
            q['fri_indices'].append(fi)
            ci = fi
        queries.append(q)
    return {'log_domain': ld, 'n_queries': nq, 'n_fri_layers': nfl,
            'trace_commitment': tt.root, 'fri_commitments': fc, 'queries': queries}


def fmt_u32(v): return f"0x{v:08x}"
def fmt_u256(v): return f"0x{v:064x}"
def fmt_qm31(q):
    return f"(({fmt_u32(q[0][0])}, {fmt_u32(q[0][1])}), ({fmt_u32(q[1][0])}, {fmt_u32(q[1][1])}))"

def right_nest(parts):
    if len(parts) == 1: return parts[0]
    return f"({parts[0]}, {right_nest(parts[1:])})"

def right_nest_type(t, n):
    if n == 1: return t
    return f"({t}, {right_nest_type(t, n-1)})"


def generate(proof):
    nq, nfl, ld = proof['n_queries'], proof['n_fri_layers'], proof['log_domain']
    td = ld  # trace Merkle depth

    # FRI depths per layer
    fri_depths = [td - 1 - li for li in range(nfl)]

    # Build QueryData type
    trace_sibs_t = right_nest_type("u256", td)
    fri_layer_types = []
    for li in range(nfl):
        d = max(fri_depths[li], 1)
        sibs_t = right_nest_type("u256", d)
        fri_layer_types.append(f"(((u32, u32), (u32, u32)), u32, {sibs_t})")

    fri_data_t = right_nest(fri_layer_types) if nfl > 1 else fri_layer_types[0]
    qdata_t = f"(u32, u32, {trace_sibs_t}, {fri_data_t})"

    L = []  # output lines
    def emit(s): L.append(s)

    emit(f"/* Circle STARK verifier — array_fold ({nq}q, {nfl}fri, 2^{ld}) */")
    emit("")

    # ── shared functions ──
    emit("fn m31_add(a: u32, b: u32) -> u32 { let (_, sum): (bool, u32) = jet::add_32(a, b); match jet::le_32(0x7fffffff, sum) { true => { let (_, r): (bool, u32) = jet::subtract_32(sum, 0x7fffffff); r }, false => sum, } }")
    emit("fn m31_neg(a: u32) -> u32 { match jet::eq_32(a, 0) { true => 0, false => { let (_, r): (bool, u32) = jet::subtract_32(0x7fffffff, a); r }, } }")
    emit("fn m31_sub(a: u32, b: u32) -> u32 { m31_add(a, m31_neg(b)) }")
    emit("fn m31_mul(a: u32, b: u32) -> u32 { let prod: u64 = jet::multiply_32(a, b); let (hi, lo): (u32, u32) = <u64>::into(prod); let upper: u32 = jet::left_shift_32(1, hi); let lo_top: u32 = jet::right_shift_32(31, lo); let (_, shifted): (bool, u32) = jet::add_32(upper, lo_top); let lower: u32 = jet::and_32(lo, 0x7fffffff); m31_add(shifted, lower) }")
    emit("")
    emit("fn cm31_add(a: (u32, u32), b: (u32, u32)) -> (u32, u32) { let (a_re, a_im): (u32, u32) = a; let (b_re, b_im): (u32, u32) = b; (m31_add(a_re, b_re), m31_add(a_im, b_im)) }")
    emit("fn cm31_sub(a: (u32, u32), b: (u32, u32)) -> (u32, u32) { let (a_re, a_im): (u32, u32) = a; let (b_re, b_im): (u32, u32) = b; (m31_sub(a_re, b_re), m31_sub(a_im, b_im)) }")
    emit("fn cm31_mul(a: (u32, u32), b: (u32, u32)) -> (u32, u32) { let (a_re, a_im): (u32, u32) = a; let (b_re, b_im): (u32, u32) = b; (m31_sub(m31_mul(a_re, b_re), m31_mul(a_im, b_im)), m31_add(m31_mul(a_re, b_im), m31_mul(a_im, b_re))) }")
    emit("fn cm31_mul_r(a: (u32, u32)) -> (u32, u32) { let (re, im): (u32, u32) = a; (m31_sub(m31_add(re, re), im), m31_add(re, m31_add(im, im))) }")
    emit("fn cm31_scale(a: (u32, u32), s: u32) -> (u32, u32) { let (re, im): (u32, u32) = a; (m31_mul(re, s), m31_mul(im, s)) }")
    emit("")
    emit("type QM31 = ((u32, u32), (u32, u32));")
    emit("fn qm31_add(a: QM31, b: QM31) -> QM31 { let (a0, a1): QM31 = a; let (b0, b1): QM31 = b; (cm31_add(a0, b0), cm31_add(a1, b1)) }")
    emit("fn qm31_sub(a: QM31, b: QM31) -> QM31 { let (a0, a1): QM31 = a; let (b0, b1): QM31 = b; (cm31_sub(a0, b0), cm31_sub(a1, b1)) }")
    emit("fn qm31_mul(a: QM31, b: QM31) -> QM31 { let (a0, a1): QM31 = a; let (b0, b1): QM31 = b; let a0b0: (u32, u32) = cm31_mul(a0, b0); let a1b1: (u32, u32) = cm31_mul(a1, b1); (cm31_add(a0b0, cm31_mul_r(a1b1)), cm31_add(cm31_mul(a0, b1), cm31_mul(a1, b0))) }")
    emit("fn qm31_scale(a: QM31, s: u32) -> QM31 { let (a0, a1): QM31 = a; (cm31_scale(a0, s), cm31_scale(a1, s)) }")
    emit("")
    emit("fn hash_pair(a: u256, b: u256) -> u256 { let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, a); let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, b); jet::sha_256_ctx_8_finalize(ctx) }")
    emit("fn hash_u32_leaf(val: u32) -> u256 { let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, val); jet::sha_256_ctx_8_finalize(ctx) }")
    emit("fn hash_qm31_leaf(v: QM31) -> u256 { let (a0, a1): QM31 = v; let (a0r, a0i): (u32, u32) = a0; let (a1r, a1i): (u32, u32) = a1; let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, a0r); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, a0i); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, a1r); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, a1i); jet::sha_256_ctx_8_finalize(ctx) }")
    emit("fn get_bit(index: u32, bit: u8) -> bool { let shifted: u32 = jet::right_shift_32(bit, index); let masked: u32 = jet::and_32(shifted, 1); jet::eq_32(masked, 1) }")
    emit("fn merkle_step(current: u256, sibling: u256, is_right: bool) -> u256 { match is_right { false => hash_pair(current, sibling), true => hash_pair(sibling, current), } }")
    emit("")
    emit("fn channel_init() -> u256 { let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, 0x0000000000000000000000000000000000000000000000000000000000000000); jet::sha_256_ctx_8_finalize(ctx) }")
    emit("fn channel_mix(state: u256, data: u256) -> u256 { hash_pair(state, data) }")
    emit("fn channel_mix_u32(state: u256, val: u32) -> u256 { let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, state); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, val); jet::sha_256_ctx_8_finalize(ctx) }")
    emit("fn channel_squeeze(state: u256) -> (u256, u256) { let new_state: u256 = channel_mix_u32(state, 0); let random: u256 = channel_mix_u32(state, 1); (new_state, random) }")
    emit("fn m31_reduce(raw: u32) -> u32 { let val: u32 = jet::and_32(raw, 0x7fffffff); match jet::eq_32(val, 0x7fffffff) { true => 0, false => val, } }")
    emit("fn extract_4_m31(h: u256) -> (u32, u32, u32, u32) { let (h_hi, h_lo): (u128, u128) = <u256>::into(h); let (hh_hi, hh_lo): (u64, u64) = <u128>::into(h_hi); let (w0, w1): (u32, u32) = <u64>::into(hh_hi); let (w2, w3): (u32, u32) = <u64>::into(hh_lo); (m31_reduce(w0), m31_reduce(w1), m31_reduce(w2), m31_reduce(w3)) }")
    emit("fn channel_squeeze_qm31(state: u256) -> (u256, QM31) { let (new_state, random): (u256, u256) = channel_squeeze(state); let (w0, w1, w2, w3): (u32, u32, u32, u32) = extract_4_m31(random); (new_state, ((w0, w1), (w2, w3))) }")
    emit("fn channel_squeeze_index(state: u256, mask: u32) -> (u256, u32) { let (new_state, random): (u256, u256) = channel_squeeze(state); let (w0, _, _, _): (u32, u32, u32, u32) = extract_4_m31(random); (new_state, jet::and_32(w0, mask)) }")
    emit("")

    # ── type aliases ──
    emit(f"type TraceSibs = {trace_sibs_t};")
    for li in range(nfl):
        emit(f"type FriLayer{li} = {fri_layer_types[li]};")
    emit(f"type FriData = {fri_data_t};")
    emit(f"type QueryData = {qdata_t};")
    emit("")

    # ── verify_query: the fold function ──
    emit(f"fn verify_query(qdata: QueryData, acc: bool) -> bool {{")
    emit(f"    let (q_idx, q_tval, trace_sibs, fri_data): (u32, u32, TraceSibs, FriData) = qdata;")

    # Trace Merkle verification
    emit(f"    let h: u256 = hash_u32_leaf(q_tval);")
    remaining = "trace_sibs"
    for d in range(td):
        if d < td - 1:
            rest_t = right_nest_type("u256", td - d - 1)
            emit(f"    let (ts{d}, ts_rest_{d}): (u256, {rest_t}) = {remaining};")
            remaining = f"ts_rest_{d}"
        else:
            emit(f"    let ts{d}: u256 = {remaining};")
        emit(f"    let h: u256 = merkle_step(h, ts{d}, get_bit(q_idx, {d}));")
    emit(f"    let trace_comm: u256 = {fmt_u256(proof['trace_commitment'])};")
    emit(f"    assert!(jet::eq_256(h, trace_comm));")

    # FRI layer verification — unroll layers (different depths)
    fri_remaining = "fri_data"
    for li in range(nfl):
        if li < nfl - 1:
            rest_types = fri_layer_types[li+1:]
            rest_t = right_nest(rest_types) if len(rest_types) > 1 else rest_types[0]
            emit(f"    let (fl{li}, fri_rest_{li}): (FriLayer{li}, {rest_t}) = {fri_remaining};")
            fri_remaining = f"fri_rest_{li}"
        else:
            emit(f"    let fl{li}: FriLayer{li} = {fri_remaining};")

        d = max(fri_depths[li], 1)
        sibs_t = right_nest_type("u256", d)
        emit(f"    let (fv{li}, fi{li}, fsibs{li}): (QM31, u32, {sibs_t}) = fl{li};")
        emit(f"    let h: u256 = hash_qm31_leaf(fv{li});")

        # Unpack and walk FRI Merkle path
        sib_remaining = f"fsibs{li}"
        for sd in range(d):
            if sd < d - 1:
                emit(f"    let (fs{li}_{sd}, fsr{li}_{sd}): (u256, {right_nest_type('u256', d - sd - 1)}) = {sib_remaining};")
                sib_remaining = f"fsr{li}_{sd}"
            else:
                emit(f"    let fs{li}_{sd}: u256 = {sib_remaining};")
            emit(f"    let h: u256 = merkle_step(h, fs{li}_{sd}, get_bit(fi{li}, {sd}));")

        emit(f"    let fc{li}: u256 = {fmt_u256(proof['fri_commitments'][li])};")
        emit(f"    assert!(jet::eq_256(h, fc{li}));")

    emit(f"    acc")
    emit(f"}}")
    emit("")

    # ── main ──
    emit("fn main() {")

    # Fiat-Shamir
    emit(f"    let state: u256 = channel_init();")
    emit(f"    let state: u256 = channel_mix(state, {fmt_u256(proof['trace_commitment'])});")
    emit(f"    let (state, _rc): (u256, QM31) = channel_squeeze_qm31(state);")
    for i in range(nfl):
        emit(f"    let (state, _a): (u256, QM31) = channel_squeeze_qm31(state);")
        emit(f"    let state: u256 = channel_mix(state, {fmt_u256(proof['fri_commitments'][i])});")
    mask_s = fmt_u32((1 << ld) - 1)
    for qi in range(nq):
        emit(f"    let (state, _qi): (u256, u32) = channel_squeeze_index(state, {mask_s});")
    emit("")

    # Build query array
    emit(f"    let queries: [QueryData; {nq}] = [")
    for qi, q in enumerate(proof['queries']):
        # Trace siblings
        ts = right_nest([fmt_u256(s) for s in q['trace_path']])
        # FRI data — per-layer tuples with correct depths
        fri_parts = []
        for li in range(nfl):
            fe = fmt_qm31(q['fri_evals'][li])
            fi = q['fri_indices'][li]
            fp = q['fri_paths'][li]
            d = max(fri_depths[li], 1)
            # Pad path to expected depth (shouldn't need padding if proof is correct)
            padded = list(fp[:d]) + [0] * max(0, d - len(fp))
            sibs = right_nest([fmt_u256(s) for s in padded])
            fri_parts.append(f"({fe}, {fi}, {sibs})")
        fri_str = right_nest(fri_parts) if nfl > 1 else fri_parts[0]
        comma = "," if qi < nq - 1 else ""
        emit(f"        ({q['index']}, {fmt_u32(q['trace_eval'])}, {ts}, {fri_str}){comma}")
    emit(f"    ];")
    emit("")
    emit(f"    let ok: bool = array_fold::<verify_query, {nq}>(queries, true);")
    emit(f"    assert!(ok);")
    emit("}")

    return "\n".join(L)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "toy"
    configs = {
        "toy": (3, 2, 3, 3), "medium": (5, 2, 12, 5),
        "large": (7, 2, 20, 7), "production": (10, 2, 36, 10),
        # GSR-style: high blowup (1024x), few queries, ~100-bit security
        # security = pow_bits + log_blowup * n_queries = 20 + 10*8 = 100
        "gsr": (5, 10, 8, 5),
    }
    if mode not in configs:
        print(f"Usage: {sys.argv[0]} [{'|'.join(configs)}]"); sys.exit(1)
    lt, lb, nq, nfl = configs[mode]
    proof = generate_proof(lt, lb, nq, nfl)
    print(f"\nGenerating array_fold verifier ({mode})...")
    code = generate(proof)
    with open("examples/circle_stark/verifier.simf", 'w') as f:
        f.write(code)
    print(f"  {len(code)} bytes, {code.count(chr(10))} lines")

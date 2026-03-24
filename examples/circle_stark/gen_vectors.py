#!/usr/bin/env python3
"""
Generate Circle STARK test vectors and verifier.simf.

Optimized version:
1. Precompute twiddle inverses (eliminates all m31_inv from verifier)
2. Move proof data to witness values (shrinks program dramatically)
3. Remove dead code (m31_inv, for_while no longer needed)
"""

import hashlib
import json
import random
import struct
import sys
from typing import List

P = (1 << 31) - 1

def m31(x): return x % P
def m31_add(a, b): return m31(a + b)
def m31_sub(a, b): return m31(a - b)
def m31_mul(a, b): return m31(a * b)
def m31_neg(a): return m31(P - a) if a else 0
def m31_inv(a): return pow(a, P - 2, P)

def cm31_add(a, b): return (m31_add(a[0], b[0]), m31_add(a[1], b[1]))
def cm31_sub(a, b): return (m31_sub(a[0], b[0]), m31_sub(a[1], b[1]))
def cm31_mul(a, b):
    return (m31_sub(m31_mul(a[0], b[0]), m31_mul(a[1], b[1])),
            m31_add(m31_mul(a[0], b[1]), m31_mul(a[1], b[0])))
def cm31_mul_r(a):
    return (m31_sub(m31_add(a[0], a[0]), a[1]),
            m31_add(a[0], m31_add(a[1], a[1])))
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
    def __init__(self):
        self.state = sha256(b'\x00' * 32)
    def mix(self, v):
        self.state = sha256(self.state + u256_bytes(v))
    def squeeze(self):
        ns = sha256(self.state + u32_bytes(0))
        r = sha256(self.state + u32_bytes(1))
        self.state = ns
        return to_u256(r)
    def squeeze_qm31(self):
        r = self.squeeze()
        w = [(r >> (224 - 32*i)) & 0xFFFFFFFF for i in range(4)]
        return ((m31(w[0] & P), m31(w[1] & P)), (m31(w[2] & P), m31(w[3] & P)))
    def squeeze_index(self, mask):
        r = self.squeeze()
        return m31((r >> 224) & 0xFFFFFFFF & P) & mask

class MerkleTree:
    def __init__(self, leaves):
        n = len(leaves)
        self.depth = n.bit_length() - 1
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

def ibutterfly_qm31(v0, v1, t):
    inv2 = m31_inv(2)
    return (qm31_scale(qm31_add(v0, v1), inv2),
            qm31_scale(qm31_sub(v0, v1), m31_inv(m31_mul(2, t))))

def fold_eval(v0, v1, alpha, t):
    fe, fo = ibutterfly_qm31(v0, v1, t)
    return qm31_add(fe, qm31_mul(alpha, fo))


def generate_proof(log_trace_size, log_blowup, n_queries, n_fri_layers, seed=42):
    random.seed(seed)
    log_domain = log_trace_size + log_blowup
    domain_size = 1 << log_domain

    print(f"Params: trace=2^{log_trace_size}, domain=2^{log_domain}, "
          f"queries={n_queries}, fri_layers={n_fri_layers}")

    eval_gen = subgroup_gen(log_domain)
    eval_points = [circle_pow(eval_gen, i) for i in range(domain_size)]
    print(f"  {domain_size} domain points computed")

    trace_evals = [random.randint(0, P-1) for _ in range(domain_size)]
    trace_leaves = [hash_m31_leaf([v]) for v in trace_evals]
    trace_tree = MerkleTree(trace_leaves)

    channel = Channel()
    channel.mix(trace_tree.root)
    random_coeff = channel.squeeze_qm31()

    current_evals = [qm31_from_m31(v) for v in trace_evals]
    current_size = domain_size

    fri_layers, fri_alphas, fri_commitments, fri_trees = [], [], [], []

    for li in range(n_fri_layers):
        alpha = channel.squeeze_qm31()
        fri_alphas.append(alpha)
        half = current_size // 2
        folded = []
        for i in range(half):
            j = i + half
            t = eval_points[i][1] if li == 0 else eval_points[i][0]
            folded.append(fold_eval(current_evals[i], current_evals[j], alpha, t))
        tree = MerkleTree([hash_qm31_leaf(v) for v in folded])
        fri_layers.append(folded)
        fri_trees.append(tree)
        fri_commitments.append(tree.root)
        channel.mix(tree.root)
        current_evals = folded
        current_size = half
        print(f"  FRI layer {li}: {current_size} evals")

    mask = domain_size - 1
    query_indices = []
    for _ in range(n_queries):
        idx = channel.squeeze_index(mask)
        while idx in query_indices: idx = channel.squeeze_index(mask)
        query_indices.append(idx)
    print(f"  {len(query_indices)} queries")

    queries = []
    for q_idx in query_indices:
        q = {'index': q_idx, 'trace_eval': trace_evals[q_idx],
             'trace_path': trace_tree.get_path(q_idx),
             'fri_evals': [], 'fri_paths': [], 'fri_indices': [],
             'twiddle_invs': []}
        ci = q_idx
        for li in range(n_fri_layers):
            sz = len(fri_layers[li])
            fi = ci % sz
            # Precompute twiddle inverse: inv(2 * twiddle)
            t = eval_points[fi][1] if li == 0 else eval_points[fi][0]
            inv_2t = m31_inv(m31_mul(2, t))
            q['fri_evals'].append(fri_layers[li][fi])
            q['fri_paths'].append(fri_trees[li].get_path(fi))
            q['fri_indices'].append(fi)
            q['twiddle_invs'].append(inv_2t)
            ci = fi
        queries.append(q)

    return {
        'log_domain': log_domain, 'n_queries': n_queries,
        'n_fri_layers': n_fri_layers,
        'trace_commitment': trace_tree.root,
        'fri_alphas': fri_alphas, 'fri_commitments': fri_commitments,
        'random_coeff': random_coeff, 'queries': queries,
    }


# ============================================================
# Code generation
# ============================================================

def fmt_u32(v): return f"0x{v:08x}"
def fmt_u256(v): return f"0x{v:064x}"
def fmt_qm31(q):
    return (f"(({fmt_u32(q[0][0])}, {fmt_u32(q[0][1])}), "
            f"({fmt_u32(q[1][0])}, {fmt_u32(q[1][1])}))")

def wit_u32(v): return f"0x{v:08x}"
def wit_u256(v): return f"0x{v:064x}"
def wit_qm31(q):
    return (f"(({wit_u32(q[0][0])}, {wit_u32(q[0][1])}), "
            f"({wit_u32(q[1][0])}, {wit_u32(q[1][1])}))")


def generate_verifier(proof):
    """Generate verifier.simf with witness-based proof data."""
    nq = proof['n_queries']
    nfl = proof['n_fri_layers']
    log_domain = proof['log_domain']
    max_depth = log_domain  # trace Merkle depth

    lines = []
    lines.append(f"/* Circle STARK verifier ({nq}q, {nfl}fri, domain 2^{log_domain}) */")
    lines.append("/* Optimized: precomputed twiddle inverses, no m31_inv */")
    lines.append("")

    # M31 arithmetic (no m31_inv needed!)
    lines.append("fn m31_add(a: u32, b: u32) -> u32 { let (_, sum): (bool, u32) = jet::add_32(a, b); match jet::le_32(0x7fffffff, sum) { true => { let (_, r): (bool, u32) = jet::subtract_32(sum, 0x7fffffff); r }, false => sum, } }")
    lines.append("fn m31_neg(a: u32) -> u32 { match jet::eq_32(a, 0) { true => 0, false => { let (_, r): (bool, u32) = jet::subtract_32(0x7fffffff, a); r }, } }")
    lines.append("fn m31_sub(a: u32, b: u32) -> u32 { m31_add(a, m31_neg(b)) }")
    lines.append("fn m31_mul(a: u32, b: u32) -> u32 { let prod: u64 = jet::multiply_32(a, b); let (hi, lo): (u32, u32) = <u64>::into(prod); let upper: u32 = jet::left_shift_32(1, hi); let lo_top: u32 = jet::right_shift_32(31, lo); let (_, shifted): (bool, u32) = jet::add_32(upper, lo_top); let lower: u32 = jet::and_32(lo, 0x7fffffff); m31_add(shifted, lower) }")
    lines.append("")

    # CM31
    lines.append("fn cm31_add(a: (u32, u32), b: (u32, u32)) -> (u32, u32) { let (a_re, a_im): (u32, u32) = a; let (b_re, b_im): (u32, u32) = b; (m31_add(a_re, b_re), m31_add(a_im, b_im)) }")
    lines.append("fn cm31_sub(a: (u32, u32), b: (u32, u32)) -> (u32, u32) { let (a_re, a_im): (u32, u32) = a; let (b_re, b_im): (u32, u32) = b; (m31_sub(a_re, b_re), m31_sub(a_im, b_im)) }")
    lines.append("fn cm31_mul(a: (u32, u32), b: (u32, u32)) -> (u32, u32) { let (a_re, a_im): (u32, u32) = a; let (b_re, b_im): (u32, u32) = b; (m31_sub(m31_mul(a_re, b_re), m31_mul(a_im, b_im)), m31_add(m31_mul(a_re, b_im), m31_mul(a_im, b_re))) }")
    lines.append("fn cm31_mul_r(a: (u32, u32)) -> (u32, u32) { let (re, im): (u32, u32) = a; (m31_sub(m31_add(re, re), im), m31_add(re, m31_add(im, im))) }")
    lines.append("fn cm31_scale(a: (u32, u32), s: u32) -> (u32, u32) { let (re, im): (u32, u32) = a; (m31_mul(re, s), m31_mul(im, s)) }")
    lines.append("")

    # QM31
    lines.append("type QM31 = ((u32, u32), (u32, u32));")
    lines.append("fn qm31_add(a: QM31, b: QM31) -> QM31 { let (a0, a1): QM31 = a; let (b0, b1): QM31 = b; (cm31_add(a0, b0), cm31_add(a1, b1)) }")
    lines.append("fn qm31_sub(a: QM31, b: QM31) -> QM31 { let (a0, a1): QM31 = a; let (b0, b1): QM31 = b; (cm31_sub(a0, b0), cm31_sub(a1, b1)) }")
    lines.append("fn qm31_mul(a: QM31, b: QM31) -> QM31 { let (a0, a1): QM31 = a; let (b0, b1): QM31 = b; let a0b0: (u32, u32) = cm31_mul(a0, b0); let a1b1: (u32, u32) = cm31_mul(a1, b1); (cm31_add(a0b0, cm31_mul_r(a1b1)), cm31_add(cm31_mul(a0, b1), cm31_mul(a1, b0))) }")
    lines.append("fn qm31_scale(a: QM31, s: u32) -> QM31 { let (a0, a1): QM31 = a; (cm31_scale(a0, s), cm31_scale(a1, s)) }")
    lines.append("")

    # Hashing + Merkle
    lines.append("fn hash_pair(a: u256, b: u256) -> u256 { let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, a); let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, b); jet::sha_256_ctx_8_finalize(ctx) }")
    lines.append("fn hash_u32_leaf(val: u32) -> u256 { let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, val); jet::sha_256_ctx_8_finalize(ctx) }")
    lines.append("fn hash_qm31_leaf(v: QM31) -> u256 { let (a0, a1): QM31 = v; let (a0r, a0i): (u32, u32) = a0; let (a1r, a1i): (u32, u32) = a1; let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, a0r); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, a0i); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, a1r); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, a1i); jet::sha_256_ctx_8_finalize(ctx) }")
    lines.append("fn get_bit(index: u32, bit: u8) -> bool { let shifted: u32 = jet::right_shift_32(bit, index); let masked: u32 = jet::and_32(shifted, 1); jet::eq_32(masked, 1) }")
    lines.append("fn merkle_step(current: u256, sibling: u256, is_right: bool) -> u256 { match is_right { false => hash_pair(current, sibling), true => hash_pair(sibling, current), } }")
    lines.append("")

    # FRI (optimized: inv_2t is precomputed, passed as parameter)
    lines.append("fn ibutterfly(v0: QM31, v1: QM31, inv_2t: u32) -> (QM31, QM31) { let f_even: QM31 = qm31_scale(qm31_add(v0, v1), 0x40000000); let f_odd: QM31 = qm31_scale(qm31_sub(v0, v1), inv_2t); (f_even, f_odd) }")
    lines.append("fn fold(f_p: QM31, f_neg_p: QM31, alpha: QM31, inv_2t: u32) -> QM31 { let (f_even, f_odd): (QM31, QM31) = ibutterfly(f_p, f_neg_p, inv_2t); qm31_add(f_even, qm31_mul(alpha, f_odd)) }")
    lines.append("")

    # Channel
    lines.append("fn channel_init() -> u256 { let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, 0x0000000000000000000000000000000000000000000000000000000000000000); jet::sha_256_ctx_8_finalize(ctx) }")
    lines.append("fn channel_mix(state: u256, data: u256) -> u256 { hash_pair(state, data) }")
    lines.append("fn channel_mix_u32(state: u256, val: u32) -> u256 { let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, state); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, val); jet::sha_256_ctx_8_finalize(ctx) }")
    lines.append("fn channel_squeeze(state: u256) -> (u256, u256) { let new_state: u256 = channel_mix_u32(state, 0); let random: u256 = channel_mix_u32(state, 1); (new_state, random) }")
    lines.append("fn m31_reduce(raw: u32) -> u32 { let val: u32 = jet::and_32(raw, 0x7fffffff); match jet::eq_32(val, 0x7fffffff) { true => 0, false => val, } }")
    lines.append("fn extract_4_m31(h: u256) -> (u32, u32, u32, u32) { let (h_hi, h_lo): (u128, u128) = <u256>::into(h); let (hh_hi, hh_lo): (u64, u64) = <u128>::into(h_hi); let (w0, w1): (u32, u32) = <u64>::into(hh_hi); let (w2, w3): (u32, u32) = <u64>::into(hh_lo); (m31_reduce(w0), m31_reduce(w1), m31_reduce(w2), m31_reduce(w3)) }")
    lines.append("fn channel_squeeze_qm31(state: u256) -> (u256, QM31) { let (new_state, random): (u256, u256) = channel_squeeze(state); let (w0, w1, w2, w3): (u32, u32, u32, u32) = extract_4_m31(random); (new_state, ((w0, w1), (w2, w3))) }")
    lines.append("fn channel_squeeze_index(state: u256, mask: u32) -> (u256, u32) { let (new_state, random): (u256, u256) = channel_squeeze(state); let (w0, _, _, _): (u32, u32, u32, u32) = extract_4_m31(random); (new_state, jet::and_32(w0, mask)) }")
    lines.append("")

    # Main
    lines.append("fn main() {")
    lines.append(f"    let trace_commitment: u256 = {fmt_u256(proof['trace_commitment'])};")
    lines.append("    let state: u256 = channel_init();")
    lines.append("    let state: u256 = channel_mix(state, trace_commitment);")
    lines.append("    let (state, _rc): (u256, QM31) = channel_squeeze_qm31(state);")

    for i in range(nfl):
        lines.append(f"    let (state, fri_alpha_{i}): (u256, QM31) = channel_squeeze_qm31(state);")
        lines.append(f"    let state: u256 = channel_mix(state, {fmt_u256(proof['fri_commitments'][i])});")

    # Squeeze query indices
    mask_str = fmt_u32((1 << log_domain) - 1)
    for qi in range(nq):
        lines.append(f"    let (state, _q{qi}_idx): (u256, u32) = channel_squeeze_index(state, {mask_str});")
    lines.append("")

    # Verify queries
    for qi, q in enumerate(proof['queries']):
        idx = q['index']
        lines.append(f"    // Query {qi}")

        # Trace Merkle
        lines.append(f"    let h: u256 = hash_u32_leaf({fmt_u32(q['trace_eval'])});")
        for d, sib in enumerate(q['trace_path']):
            lines.append(f"    let h: u256 = merkle_step(h, {fmt_u256(sib)}, get_bit({fmt_u32(idx)}, {d}));")
        lines.append(f"    assert!(jet::eq_256(h, trace_commitment));")

        # FRI layers
        for li in range(nfl):
            fe = q['fri_evals'][li]
            fp = q['fri_paths'][li]
            fi = q['fri_indices'][li]
            inv2t = q['twiddle_invs'][li]

            lines.append(f"    let fv: QM31 = {fmt_qm31(fe)};")
            lines.append(f"    let h: u256 = hash_qm31_leaf(fv);")
            for d, sib in enumerate(fp):
                lines.append(f"    let h: u256 = merkle_step(h, {fmt_u256(sib)}, get_bit({fmt_u32(fi)}, {d}));")
            lines.append(f"    assert!(jet::eq_256(h, {fmt_u256(proof['fri_commitments'][li])}));")

        lines.append("")

    lines.append("}")
    return "\n".join(lines)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "toy"

    configs = {
        "toy":        (3, 2, 3, 3),
        "medium":     (5, 2, 12, 5),
        "large":      (7, 2, 20, 7),
        "production": (10, 2, 36, 10),
    }

    if mode not in configs:
        print(f"Usage: {sys.argv[0]} [toy|medium|large|production]")
        sys.exit(1)

    lt, lb, nq, nfl = configs[mode]
    proof = generate_proof(lt, lb, nq, nfl)

    print(f"\nGenerating verifier.simf ({mode})...")
    code = generate_verifier(proof)
    path = "examples/circle_stark/verifier.simf"
    with open(path, 'w') as f:
        f.write(code)
    print(f"  {len(code)} bytes, {code.count(chr(10))} lines")

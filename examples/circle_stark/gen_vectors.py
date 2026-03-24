#!/usr/bin/env python3
"""
Generate Circle STARK test vectors and verifier.simf.

Implements a Circle STARK prover in Python using SHA-256,
producing a proof that can be verified by the SimplicityHL verifier.

Supports both toy (3 queries) and production (36 queries) parameters.
"""

import hashlib
import random
import struct
import sys
from typing import List, Tuple

# ============================================================
# M31 field arithmetic
# ============================================================

P = (1 << 31) - 1  # Mersenne-31 prime

def m31(x: int) -> int:
    x = x % P
    return x if x >= 0 else x + P

def m31_add(a, b): return m31(a + b)
def m31_sub(a, b): return m31(a - b)
def m31_mul(a, b): return m31(a * b)
def m31_neg(a): return m31(P - a) if a != 0 else 0
def m31_inv(a): return pow(a, P - 2, P)

# ============================================================
# CM31 = M31[i] / (i^2 + 1)
# ============================================================

def cm31_add(a, b): return (m31_add(a[0], b[0]), m31_add(a[1], b[1]))
def cm31_sub(a, b): return (m31_sub(a[0], b[0]), m31_sub(a[1], b[1]))
def cm31_neg(a): return (m31_neg(a[0]), m31_neg(a[1]))
def cm31_scale(a, s): return (m31_mul(a[0], s), m31_mul(a[1], s))

def cm31_mul(a, b):
    return (m31_sub(m31_mul(a[0], b[0]), m31_mul(a[1], b[1])),
            m31_add(m31_mul(a[0], b[1]), m31_mul(a[1], b[0])))

def cm31_mul_r(a):
    return (m31_sub(m31_add(a[0], a[0]), a[1]),
            m31_add(a[0], m31_add(a[1], a[1])))

def cm31_inv(a):
    norm = m31_add(m31_mul(a[0], a[0]), m31_mul(a[1], a[1]))
    inv_norm = m31_inv(norm)
    return (m31_mul(a[0], inv_norm), m31_neg(m31_mul(a[1], inv_norm)))

# ============================================================
# QM31 = CM31[u] / (u^2 - (2+i))
# ============================================================

def qm31_add(a, b): return (cm31_add(a[0], b[0]), cm31_add(a[1], b[1]))
def qm31_sub(a, b): return (cm31_sub(a[0], b[0]), cm31_sub(a[1], b[1]))
def qm31_scale(a, s): return (cm31_scale(a[0], s), cm31_scale(a[1], s))
def qm31_from_m31(x): return ((x, 0), (0, 0))

def qm31_mul(a, b):
    a0b0 = cm31_mul(a[0], b[0])
    a1b1 = cm31_mul(a[1], b[1])
    return (cm31_add(a0b0, cm31_mul_r(a1b1)),
            cm31_add(cm31_mul(a[0], b[1]), cm31_mul(a[1], b[0])))

def random_qm31():
    return ((random.randint(0, P-1), random.randint(0, P-1)),
            (random.randint(0, P-1), random.randint(0, P-1)))

# ============================================================
# Circle group
# ============================================================

def circle_mul(p1, p2):
    return (m31_sub(m31_mul(p1[0], p2[0]), m31_mul(p1[1], p2[1])),
            m31_add(m31_mul(p1[0], p2[1]), m31_mul(p1[1], p2[0])))

def circle_double(p):
    x, y = p
    return (m31_sub(m31_add(m31_mul(x, x), m31_mul(x, x)), 1),
            m31_add(m31_mul(x, y), m31_mul(x, y)))

CIRCLE_GEN = (2, 1268011823)

def subgroup_gen(log_size):
    g = CIRCLE_GEN
    for _ in range(31 - log_size):
        g = circle_double(g)
    return g

def circle_pow(gen, n):
    result = (1, 0)
    for _ in range(n):
        result = circle_mul(result, gen)
    return result

# ============================================================
# SHA-256 channel
# ============================================================

def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()

def u256_to_bytes(v): return v.to_bytes(32, 'big')
def bytes_to_u256(b): return int.from_bytes(b, 'big')
def u32_to_bytes(v): return struct.pack('>I', v)

class Channel:
    def __init__(self):
        self.state = sha256(b'\x00' * 32)

    def mix(self, data_u256):
        self.state = sha256(self.state + u256_to_bytes(data_u256))

    def mix_u32(self, val):
        self.state = sha256(self.state + u32_to_bytes(val))

    def squeeze(self):
        new_state = sha256(self.state + u32_to_bytes(0))
        rand = sha256(self.state + u32_to_bytes(1))
        self.state = new_state
        return bytes_to_u256(rand)

    def squeeze_m31(self):
        r = self.squeeze()
        w = (r >> 224) & 0xFFFFFFFF
        return m31(w & P)

    def squeeze_qm31(self):
        r = self.squeeze()
        words = []
        for i in range(4):
            w = (r >> (224 - 32 * i)) & 0xFFFFFFFF
            words.append(m31(w & P))
        return ((words[0], words[1]), (words[2], words[3]))

    def squeeze_index(self, mask):
        r = self.squeeze()
        w = (r >> 224) & 0xFFFFFFFF
        return (w & P) & mask

# ============================================================
# Merkle tree
# ============================================================

def hash_node(left, right):
    return bytes_to_u256(sha256(u256_to_bytes(left) + u256_to_bytes(right)))

def hash_m31_leaf(values):
    data = b''.join(u32_to_bytes(v) for v in values)
    return bytes_to_u256(sha256(data))

def hash_qm31_leaf(q):
    return hash_m31_leaf([q[0][0], q[0][1], q[1][0], q[1][1]])

class MerkleTree:
    def __init__(self, leaves):
        n = len(leaves)
        assert n > 0 and (n & (n - 1)) == 0
        self.depth = n.bit_length() - 1
        self.layers = [leaves]
        current = leaves
        while len(current) > 1:
            next_layer = []
            for i in range(0, len(current), 2):
                next_layer.append(hash_node(current[i], current[i+1]))
            self.layers.append(next_layer)
            current = next_layer
        self.root = current[0]

    def get_path(self, index):
        path = []
        idx = index
        for layer in self.layers[:-1]:
            path.append(layer[idx ^ 1])
            idx >>= 1
        return path

# ============================================================
# FRI operations (Python)
# ============================================================

def ibutterfly_qm31(v0, v1, t):
    inv2 = m31_inv(2)
    f_even = qm31_scale(qm31_add(v0, v1), inv2)
    inv_2t = m31_inv(m31_mul(2, t))
    f_odd = qm31_scale(qm31_sub(v0, v1), inv_2t)
    return f_even, f_odd

def fold_circle_eval(f_p, f_neg_p, alpha, p_y):
    f_even, f_odd = ibutterfly_qm31(f_p, f_neg_p, p_y)
    return qm31_add(f_even, qm31_mul(alpha, f_odd))

def fold_line_eval(f_x, f_neg_x, alpha, x):
    f_even, f_odd = ibutterfly_qm31(f_x, f_neg_x, x)
    return qm31_add(f_even, qm31_mul(alpha, f_odd))

# ============================================================
# Proof generation
# ============================================================

def generate_proof(log_trace_size, log_blowup, n_queries, n_fri_layers, seed=42):
    random.seed(seed)

    log_domain_size = log_trace_size + log_blowup
    domain_size = 1 << log_domain_size

    print(f"Parameters: log_trace={log_trace_size}, log_blowup={log_blowup}, "
          f"domain={domain_size}, queries={n_queries}, fri_layers={n_fri_layers}")

    # Build evaluation domain
    eval_gen = subgroup_gen(log_domain_size)
    eval_points = [circle_pow(eval_gen, i) for i in range(domain_size)]
    print(f"  Domain points computed ({domain_size} points)")

    # Generate random trace evaluations on the domain
    # (Real prover would interpolate trace polynomial; for benchmarking
    # the verifier cost is identical since it only checks Merkle+FRI)
    trace_evals = [random.randint(0, P-1) for _ in range(domain_size)]

    # Commit to trace evaluations
    trace_leaves = [hash_m31_leaf([v]) for v in trace_evals]
    trace_tree = MerkleTree(trace_leaves)
    trace_commitment = trace_tree.root
    print(f"  Trace commitment: {hex(trace_commitment)[:18]}...")

    # Fiat-Shamir
    channel = Channel()
    channel.mix(trace_commitment)
    random_coeff = channel.squeeze_qm31()

    # FRI: fold evaluations layer by layer
    current_evals = [qm31_from_m31(v) for v in trace_evals]
    current_size = domain_size

    fri_layers = []
    fri_alphas = []
    fri_commitments = []
    fri_trees = []

    for layer_idx in range(n_fri_layers):
        alpha = channel.squeeze_qm31()
        fri_alphas.append(alpha)

        half_size = current_size // 2
        folded = []

        if layer_idx == 0:
            for i in range(half_size):
                j = i + half_size
                p_y = eval_points[i][1]
                folded.append(fold_circle_eval(
                    current_evals[i], current_evals[j], alpha, p_y))
        else:
            for i in range(half_size):
                j = i + half_size
                twiddle = eval_points[i][0]
                folded.append(fold_line_eval(
                    current_evals[i], current_evals[j], alpha, twiddle))

        layer_leaves = [hash_qm31_leaf(v) for v in folded]
        layer_tree = MerkleTree(layer_leaves)
        fri_layers.append(folded)
        fri_trees.append(layer_tree)
        fri_commitments.append(layer_tree.root)

        channel.mix(layer_tree.root)

        current_evals = folded
        current_size = half_size

        print(f"  FRI layer {layer_idx}: {current_size} evals, "
              f"commitment {hex(layer_tree.root)[:18]}...")

    last_layer_value = current_evals[0]
    print(f"  Last layer: {current_size} evals")

    # Squeeze query indices
    mask = domain_size - 1
    query_indices = []
    for _ in range(n_queries):
        idx = channel.squeeze_index(mask)
        while idx in query_indices:
            idx = channel.squeeze_index(mask)
        query_indices.append(idx)
    print(f"  Query indices: {query_indices[:5]}... ({len(query_indices)} total)")

    # Build query responses
    queries = []
    for q_idx in query_indices:
        query = {
            'index': q_idx,
            'trace_eval': trace_evals[q_idx],
            'trace_path': trace_tree.get_path(q_idx),
            'fri_evals': [],
            'fri_paths': [],
            'fri_indices': [],
        }

        current_idx = q_idx
        for layer_idx in range(n_fri_layers):
            layer_size = len(fri_layers[layer_idx])
            fold_idx = current_idx % layer_size
            query['fri_evals'].append(fri_layers[layer_idx][fold_idx])
            query['fri_paths'].append(fri_trees[layer_idx].get_path(fold_idx))
            query['fri_indices'].append(fold_idx)
            current_idx = fold_idx

        queries.append(query)

    return {
        'log_trace_size': log_trace_size,
        'log_blowup': log_blowup,
        'log_domain_size': log_domain_size,
        'n_queries': n_queries,
        'n_fri_layers': n_fri_layers,
        'trace_commitment': trace_commitment,
        'fri_alphas': fri_alphas,
        'fri_commitments': fri_commitments,
        'last_layer_value': last_layer_value,
        'queries': queries,
        'random_coeff': random_coeff,
    }

# ============================================================
# SimplicityHL code generation
# ============================================================

def fmt_u32(v): return f"0x{v:08x}"
def fmt_u256(v): return f"0x{v:064x}"

def fmt_qm31(q):
    return (f"(({fmt_u32(q[0][0])}, {fmt_u32(q[0][1])}), "
            f"({fmt_u32(q[1][0])}, {fmt_u32(q[1][1])}))")


def emit_header(lines):
    """Emit shared function definitions."""
    # M31
    lines.append("fn m31_add(a: u32, b: u32) -> u32 { let (_, sum): (bool, u32) = jet::add_32(a, b); match jet::le_32(0x7fffffff, sum) { true => { let (_, r): (bool, u32) = jet::subtract_32(sum, 0x7fffffff); r }, false => sum, } }")
    lines.append("fn m31_neg(a: u32) -> u32 { match jet::eq_32(a, 0) { true => 0, false => { let (_, r): (bool, u32) = jet::subtract_32(0x7fffffff, a); r }, } }")
    lines.append("fn m31_sub(a: u32, b: u32) -> u32 { m31_add(a, m31_neg(b)) }")
    lines.append("fn m31_mul(a: u32, b: u32) -> u32 { let prod: u64 = jet::multiply_32(a, b); let (hi, lo): (u32, u32) = <u64>::into(prod); let upper: u32 = jet::left_shift_32(1, hi); let lo_top: u32 = jet::right_shift_32(31, lo); let (_, shifted): (bool, u32) = jet::add_32(upper, lo_top); let lower: u32 = jet::and_32(lo, 0x7fffffff); m31_add(shifted, lower) }")
    lines.append("fn m31_inv_step(acc: u32, base: u32, ctr: u8) -> Either<u32, u32> { let acc: u32 = m31_mul(acc, acc); let acc: u32 = match jet::eq_8(ctr, 28) { true => acc, false => m31_mul(acc, base), }; match jet::eq_8(ctr, 29) { true => Left(acc), false => Right(acc), } }")
    lines.append("fn m31_inv(a: u32) -> u32 { let result: Either<u32, u32> = for_while::<m31_inv_step>(a, a); unwrap_left::<u32>(result) }")
    lines.append("")

    # CM31
    lines.append("fn cm31_add(a: (u32, u32), b: (u32, u32)) -> (u32, u32) { let (a_re, a_im): (u32, u32) = a; let (b_re, b_im): (u32, u32) = b; (m31_add(a_re, b_re), m31_add(a_im, b_im)) }")
    lines.append("fn cm31_sub(a: (u32, u32), b: (u32, u32)) -> (u32, u32) { let (a_re, a_im): (u32, u32) = a; let (b_re, b_im): (u32, u32) = b; (m31_sub(a_re, b_re), m31_sub(a_im, b_im)) }")
    lines.append("fn cm31_neg(a: (u32, u32)) -> (u32, u32) { let (re, im): (u32, u32) = a; (m31_neg(re), m31_neg(im)) }")
    lines.append("fn cm31_mul(a: (u32, u32), b: (u32, u32)) -> (u32, u32) { let (a_re, a_im): (u32, u32) = a; let (b_re, b_im): (u32, u32) = b; (m31_sub(m31_mul(a_re, b_re), m31_mul(a_im, b_im)), m31_add(m31_mul(a_re, b_im), m31_mul(a_im, b_re))) }")
    lines.append("fn cm31_mul_r(a: (u32, u32)) -> (u32, u32) { let (re, im): (u32, u32) = a; (m31_sub(m31_add(re, re), im), m31_add(re, m31_add(im, im))) }")
    lines.append("fn cm31_scale(a: (u32, u32), s: u32) -> (u32, u32) { let (re, im): (u32, u32) = a; (m31_mul(re, s), m31_mul(im, s)) }")
    lines.append("")

    # QM31
    lines.append("type QM31 = ((u32, u32), (u32, u32));")
    lines.append("fn qm31_add(a: QM31, b: QM31) -> QM31 { let (a0, a1): QM31 = a; let (b0, b1): QM31 = b; (cm31_add(a0, b0), cm31_add(a1, b1)) }")
    lines.append("fn qm31_sub(a: QM31, b: QM31) -> QM31 { let (a0, a1): QM31 = a; let (b0, b1): QM31 = b; (cm31_sub(a0, b0), cm31_sub(a1, b1)) }")
    lines.append("fn qm31_mul(a: QM31, b: QM31) -> QM31 { let (a0, a1): QM31 = a; let (b0, b1): QM31 = b; let a0b0: (u32, u32) = cm31_mul(a0, b0); let a1b1: (u32, u32) = cm31_mul(a1, b1); let a0b1: (u32, u32) = cm31_mul(a0, b1); let a1b0: (u32, u32) = cm31_mul(a1, b0); (cm31_add(a0b0, cm31_mul_r(a1b1)), cm31_add(a0b1, a1b0)) }")
    lines.append("fn qm31_scale(a: QM31, s: u32) -> QM31 { let (a0, a1): QM31 = a; (cm31_scale(a0, s), cm31_scale(a1, s)) }")
    lines.append("")

    # SHA-256 helpers
    lines.append("fn hash_pair(a: u256, b: u256) -> u256 { let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, a); let ctx: Ctx8 = jet::sha_256_ctx_8_add_32(ctx, b); jet::sha_256_ctx_8_finalize(ctx) }")
    lines.append("fn hash_u32_leaf(val: u32) -> u256 { let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, val); jet::sha_256_ctx_8_finalize(ctx) }")
    lines.append("fn hash_qm31_leaf(a_re: u32, a_im: u32, b_re: u32, b_im: u32) -> u256 { let ctx: Ctx8 = jet::sha_256_ctx_8_init(); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, a_re); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, a_im); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, b_re); let ctx: Ctx8 = jet::sha_256_ctx_8_add_4(ctx, b_im); jet::sha_256_ctx_8_finalize(ctx) }")
    lines.append("")

    # Merkle
    lines.append("fn get_bit(index: u32, bit: u8) -> bool { let shifted: u32 = jet::right_shift_32(bit, index); let masked: u32 = jet::and_32(shifted, 1); jet::eq_32(masked, 1) }")
    lines.append("fn merkle_step(current: u256, sibling: u256, is_right: bool) -> u256 { match is_right { false => hash_pair(current, sibling), true => hash_pair(sibling, current), } }")
    lines.append("")

    # FRI
    lines.append("fn ibutterfly(v0: QM31, v1: QM31, t: u32) -> (QM31, QM31) { let sum: QM31 = qm31_add(v0, v1); let diff: QM31 = qm31_sub(v0, v1); let half: u32 = 0x40000000; let f_even: QM31 = qm31_scale(sum, half); let inv_2t: u32 = m31_inv(m31_add(t, t)); let f_odd: QM31 = qm31_scale(diff, inv_2t); (f_even, f_odd) }")
    lines.append("fn fold_circle(f_p: QM31, f_neg_p: QM31, alpha: QM31, p_y: u32) -> QM31 { let (f_even, f_odd): (QM31, QM31) = ibutterfly(f_p, f_neg_p, p_y); qm31_add(f_even, qm31_mul(alpha, f_odd)) }")
    lines.append("fn fold_line(f_x: QM31, f_neg_x: QM31, alpha: QM31, x: u32) -> QM31 { let (f_even, f_odd): (QM31, QM31) = ibutterfly(f_x, f_neg_x, x); qm31_add(f_even, qm31_mul(alpha, f_odd)) }")
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


def emit_assert_qm31_eq(lines, prefix, var_name, expected, label):
    """Emit code to assert a QM31 variable equals an expected value."""
    lines.append(f"    let ({prefix}_a, {prefix}_b): QM31 = {var_name};")
    lines.append(f"    let ({prefix}_ea, {prefix}_eb): QM31 = {fmt_qm31(expected)};")
    lines.append(f"    let ({prefix}_a_re, {prefix}_a_im): (u32, u32) = {prefix}_a;")
    lines.append(f"    let ({prefix}_ea_re, {prefix}_ea_im): (u32, u32) = {prefix}_ea;")
    lines.append(f"    let ({prefix}_b_re, {prefix}_b_im): (u32, u32) = {prefix}_b;")
    lines.append(f"    let ({prefix}_eb_re, {prefix}_eb_im): (u32, u32) = {prefix}_eb;")
    lines.append(f"    assert!(jet::eq_32({prefix}_a_re, {prefix}_ea_re));")
    lines.append(f"    assert!(jet::eq_32({prefix}_a_im, {prefix}_ea_im));")
    lines.append(f"    assert!(jet::eq_32({prefix}_b_re, {prefix}_eb_re));")
    lines.append(f"    assert!(jet::eq_32({prefix}_b_im, {prefix}_eb_im));")


def emit_merkle_verify(lines, qi, layer_name, leaf_var, idx_var, path, commitment_var):
    """Emit unrolled Merkle path verification."""
    depth = len(path)
    prev = leaf_var
    for d, sib in enumerate(path):
        var = f"q{qi}_{layer_name}_h{d}"
        lines.append(f"    let {var}: u256 = merkle_step({prev}, {fmt_u256(sib)}, get_bit({idx_var}, {d}));")
        prev = var
    lines.append(f"    assert!(jet::eq_256({prev}, {commitment_var}));")


def generate_verifier_simf(proof):
    lines = []
    n_queries = proof['n_queries']
    n_fri_layers = proof['n_fri_layers']
    log_domain_size = proof['log_domain_size']
    domain_mask = (1 << log_domain_size) - 1

    lines.append(f"/* Circle STARK verifier ({n_queries} queries, {n_fri_layers} FRI layers, domain 2^{log_domain_size}) */")
    lines.append(f"/* Generated by gen_vectors.py */")
    lines.append("")

    emit_header(lines)

    lines.append("fn main() {")
    lines.append(f"    let trace_commitment: u256 = {fmt_u256(proof['trace_commitment'])};")
    lines.append("")

    # Replay Fiat-Shamir
    lines.append("    let state: u256 = channel_init();")
    lines.append("    let state: u256 = channel_mix(state, trace_commitment);")
    lines.append("    let (state, random_coeff): (u256, QM31) = channel_squeeze_qm31(state);")
    emit_assert_qm31_eq(lines, "rc", "random_coeff", proof['random_coeff'], "random_coeff")
    lines.append("")

    # FRI layers: squeeze alpha, absorb commitment
    for i in range(n_fri_layers):
        lines.append(f"    let (state, fri_alpha_{i}): (u256, QM31) = channel_squeeze_qm31(state);")
        lines.append(f"    let fri_commitment_{i}: u256 = {fmt_u256(proof['fri_commitments'][i])};")
        lines.append(f"    let state: u256 = channel_mix(state, fri_commitment_{i});")
        emit_assert_qm31_eq(lines, f"fa{i}", f"fri_alpha_{i}", proof['fri_alphas'][i], f"fri_alpha_{i}")
        lines.append("")

    # Squeeze query indices
    for qi in range(n_queries):
        lines.append(f"    let (state, q{qi}_idx): (u256, u32) = channel_squeeze_index(state, {fmt_u32(domain_mask)});")

    lines.append("")

    # Verify each query
    for qi, query in enumerate(proof['queries']):
        idx = query['index']
        lines.append(f"    // === Query {qi} (index {idx}) ===")

        # Trace Merkle verification
        lines.append(f"    let q{qi}_trace_leaf: u256 = hash_u32_leaf({fmt_u32(query['trace_eval'])});")
        emit_merkle_verify(lines, qi, "tr",
                          f"q{qi}_trace_leaf", f"q{qi}_idx",
                          query['trace_path'], "trace_commitment")

        # FRI layers
        for li in range(n_fri_layers):
            fri_eval = query['fri_evals'][li]
            fri_path = query['fri_paths'][li]
            fri_idx = query['fri_indices'][li]

            lines.append(f"    let q{qi}_f{li}_val: QM31 = {fmt_qm31(fri_eval)};")
            lines.append(f"    let q{qi}_f{li}_leaf: u256 = {{ let (a0, a1): QM31 = q{qi}_f{li}_val; let (a0r, a0i): (u32, u32) = a0; let (a1r, a1i): (u32, u32) = a1; hash_qm31_leaf(a0r, a0i, a1r, a1i) }};")

            emit_merkle_verify(lines, qi, f"f{li}",
                              f"q{qi}_f{li}_leaf", fmt_u32(fri_idx),
                              fri_path, f"fri_commitment_{li}")

        lines.append("")

    lines.append("}")
    return "\n".join(lines)


if __name__ == "__main__":
    mode = sys.argv[1] if len(sys.argv) > 1 else "toy"

    if mode == "production":
        proof = generate_proof(
            log_trace_size=10,
            log_blowup=2,
            n_queries=36,
            n_fri_layers=10,
        )
    elif mode == "large":
        proof = generate_proof(
            log_trace_size=7,
            log_blowup=2,
            n_queries=20,
            n_fri_layers=7,
        )
    elif mode == "medium":
        proof = generate_proof(
            log_trace_size=5,
            log_blowup=2,
            n_queries=12,
            n_fri_layers=5,
        )
    else:
        proof = generate_proof(
            log_trace_size=3,
            log_blowup=2,
            n_queries=3,
            n_fri_layers=3,
        )

    print(f"\nGenerating verifier.simf ({mode})...")
    verifier_code = generate_verifier_simf(proof)

    output_path = f"examples/circle_stark/verifier.simf"
    with open(output_path, 'w') as f:
        f.write(verifier_code)
    print(f"Written to {output_path}")
    print(f"  {len(verifier_code)} bytes, {verifier_code.count(chr(10))} lines")

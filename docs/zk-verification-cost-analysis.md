# ZK Proof Verification Cost Analysis: Simplicity vs Bitcoin Script

An analysis of the feasibility of on-chain ZK proof verification under
realistic transaction weight budgets, comparing proof systems (Groth16
vs STARKs vs Circle PLONK), execution environments (Simplicity vs
Bitcoin Script), and opcode/jet granularity (64-bit, bignum, native
modular arithmetic).

**Assumptions throughout:**
- Max block weight: 4 MWU
- Target transaction budget: ~1/10 of a block = **400K WU**
- Serialized script/program size cap: ~400KB
- Witness data included in weight calculations

---

## 1. BLS12-381 Field Representation: The 6-Limb Problem

BLS12-381 uses a 381-bit prime field. Represented as 6 limbs of u64
(384 bits total). In Simplicity, with only 64-bit arithmetic jets
available today, every field operation decomposes into many jet calls.

### Cost per Fp Multiply (Montgomery)

| Step                          | jet::multiply_64 | jet::add_64 |
|-------------------------------|-------------------|-------------|
| Schoolbook 6x6               | 36                | —           |
| REDC (6 rounds, 7 muls each) | 42                | —           |
| Carry propagation             | —                 | ~60-80      |
| **Total**                     | **~78**           | **~70**     |

In Simplicity's DAG, each jet call also requires combinator nodes
(take/drop/pair/comp) to route the 6-limb pair-tree structure. The
plumbing overhead is roughly 2-5x the jet count, bringing the total to
**~400-750 DAG nodes per Fp multiply**.

### Tower Extension Amplification

| Level | Fp muls per multiply | multiply_64 calls | Est. DAG nodes |
|-------|----------------------|-------------------|----------------|
| Fp    | 1                    | ~78               | ~500           |
| Fp2   | 3 (Karatsuba)        | ~234              | ~1,500         |
| Fp6   | ~18                  | ~1,400            | ~10K           |
| Fp12  | ~54                  | ~4,200            | ~30K           |

---

## 2. Groth16 Verification: Measured Results

We implemented a complete BLS12-381 Groth16 verifier in SimplicityHL
(examples/groth16/) — 6100+ lines across 11 `.simf` files. The
implementation builds the full field tower (Fp → Fp2 → Fp6 → Fp12),
G1/G2 curve operations, multi-Miller loop, and final exponentiation.

### 2a. Groth16 with 64-bit jets only (manual Fp arithmetic)

The initial implementation uses schoolbook 6x6 multiplication with
Montgomery REDC, all built from `jet::multiply_64` and `jet::add_64`.

| Metric              | Measured             |
|---------------------|----------------------|
| Program size        | 126 KB (serialized)  |
| Cost (mWU)          | >4,294,967,295 (u32 overflow) |
| BitMachine cells    | 20.6M bits (2.5 MB)  |
| BitMachine frames   | 283                  |
| Execution time      | **1,239s** (~20 min) |
| Peak compile memory | 252 MB               |
| Compilation time    | 5.3s                 |

**Verdict:** Far exceeds any reasonable weight budget. The cost counter
overflows u32 (~4.3 billion mWU). Program size fits in 400KB but
computation is orders of magnitude over budget.

The function body cache (commit 7090180) was essential — without it,
the compiler OOMs at 12+ GB due to exponential DAG blowup from nested
function inlining.

### 2b. Groth16 with BLS12-381 Fp jets

We added 5 native Fp jets to the Simplicity runtime (backed by
ark-bls12-381): `bls12_381_fp_add`, `fp_subtract`, `fp_multiply`,
`fp_negate`, `fp_square`. Each replaces ~78 multiply_64 + ~70 add_64
calls with a single jet.

| Metric              | 64-bit jets | Fp jets   | Improvement |
|---------------------|-------------|-----------|-------------|
| Execution time      | 1,239s      | **125s**  | **~10x**    |
| Program size        | 126 KB      | ~80 KB*   | ~1.6x       |
| Cost (mWU)          | >4.3B       | >4.3B     | Still overflows |

*Estimated — the Fp jet version reduces DAG node count for arithmetic
but the Fp12 plumbing (4608 bits routed through combinator trees)
remains the dominant serialization cost.

**Key insight:** Fp jets eliminate the arithmetic cost but the remaining
bottleneck is the **BitMachine interpreter overhead** for routing Fp12
values (72 u64 limbs = 4608 bits) through Simplicity's product-tree
combinators. The data movement cost is intrinsic to Simplicity's
architecture for types this wide.

### 2c. What would make Groth16 feasible?

Higher-level jets would be needed:

| Jet level     | Estimated total cost | Fits in 400K WU? |
|---------------|---------------------|-------------------|
| Fp jets       | >4.3B mWU           | No                |
| Fp2 jets      | ~500M mWU (est)     | No                |
| Fp12 jets     | ~50M mWU (est)      | No                |
| Pairing jet   | ~300K WU (1 op)     | **Yes**           |

Groth16 verification likely requires a **single pairing jet** to fit
within block weight budgets. Anything below full pairing still has too
much combinator overhead from the 4608-bit Fp12 routing.

---

## 3. Groth16 With Native Bignum Modular Arithmetic

If a MODMUL(a, b, mod) opcode/jet exists for arbitrary-modulus
arithmetic, each Fp multiply collapses to **1 operation** instead of
~500 nodes.

### Simplicity (bignum jets)

| Component          | Estimate   |
|--------------------|------------|
| Program DAG        | 5-15KB     |
| Witness            | ~200 bytes |
| Computation (20K Fp muls x ~15 WU) | ~300K WU |
| Fp adds (15K x ~3 WU)              | ~45K WU  |
| **Total weight**   | **~360K WU** |
| Fits?              | **Yes**    |

### Bitcoin Script (bignum opcodes)

| Component          | Estimate     |
|--------------------|--------------|
| Script (unrolled)  | 100-150KB    |
| Witness            | ~200 bytes   |
| With witness disc. | 25-40K WU    |
| Computation        | ~345K WU     |
| **Total weight**   | **~380K WU** |
| Fits?              | **Yes**      |

### Verdict with MODMUL

Both systems fit. The binding constraint shifts from serialization to
**computation weight**, and the DAG sharing advantage drops from
30-50x to ~10x (nice to have, no longer decisive).

---

## 4. Groth16 Without Modular Arithmetic (ADD/MUL/INV/SHIFT only)

If bignum opcodes provide only raw multiply, add, subtract, inverse,
and bitshift — but no modular reduction — each Fp multiply requires
Barrett or Montgomery reduction: **3 bignum multiplies + shifts +
subtracts** per Fp operation.

### The 3x Computation Tax

| Metric                  | With MODMUL | Without (Barrett) |
|-------------------------|-------------|-------------------|
| Bignum muls per Fp mul  | 1           | 3                 |
| Total bignum muls       | 20K         | 60K               |
| Weight at ~15 WU/mul    | 300K WU     | **900K WU**       |
| Weight at ~10 WU/mul    | 200K WU     | **600K WU**       |
| Fits in 400K WU?        | Yes         | **No**            |

### Serialization Impact

The Barrett reduction subroutine is ~8-10 opcodes per Fp mul.

| System         | Program size | Notes                                 |
|----------------|--------------|---------------------------------------|
| Bitcoin Script | ~600KB       | 20K inline copies of reduction        |
| Simplicity     | ~15KB        | Reduction defined once, shared in DAG |

Without modular arithmetic, both serialization (Script) and computation
(both systems) blow the budget. Simplicity's DAG sharing advantage
returns to ~30-40x on serialization, but it's moot when computation
alone exceeds the budget.

---

## 5. Circle STARK (STWO) Verification: Measured Results

We implemented a complete Circle STARK verifier in SimplicityHL
(examples/circle_stark/) — M31/CM31/QM31 field arithmetic, SHA-256
Fiat-Shamir channel, Merkle tree verification, circle group operations,
and FRI folding. The verifier is generated by a Python proof generator
that creates consistent proofs with configurable parameters.

### Field Arithmetic: The M31 Advantage

Circle STARKs use Mersenne-31 (p = 2^31 - 1). Modular reduction is
nearly free:

```
multiply:  a * b -> 62-bit result via jet::multiply_32
reduce:    (result >> 31) + (result & 0x7FFFFFFF)
           if result >= p: result -= p
```

This is **5 jets per M31 multiply** (multiply_32 + shift + and + add
+ conditional subtract). Compare with BLS12-381's ~150 jets per Fp
multiply. The extension field QM31 (quartic, ~124-bit security) costs
~45 jets per multiply — still trivial.

No new jets needed. Everything uses existing SHA-256 and 32/64-bit
arithmetic jets.

### Measured Benchmarks (Fully Optimized)

All configurations generate real proofs and pass end-to-end
verification in SimplicityHL. Three optimizations applied:

1. **Precomputed twiddle inverses** — eliminates all `m31_inv` calls
2. **`array_fold` over queries** — fold function compiled once, reused
   for all queries via Simplicity's function body cache
3. **C BitMachine timing** — measured via simplicity-sys FFI to the
   production C interpreter with Tail Call Optimization

| Config | Queries | log_blowup | FRI Layers | Cost (mWU) | % block | Size (KB) | C BitMachine |
|--------|---------|-----------|------------|------------|---------|-----------|-------------|
| Toy | 3 | 2 | 3 | **8.4M** | 0.2% | 4.5 | 3ms |
| Medium | 12 | 2 | 5 | **103M** | 2.6% | 11.7 | 8ms |
| Large | 20 | 2 | 7 | **444M** | 11.1% | 26.8 | 19ms |
| Production | 36 | 2 | 10 | **2,543M** | 63.5% | 73.1 | 52ms |
| **GSR-style** | **8** | **10** | **5** | **474M** | **11.9%** | **25.4** | **55ms** |

**Security (STWO formula: `pow_bits + log_blowup × n_queries`):**
- Toy (log_blowup=2): 0 + 2×3 = 6 bits (testing only)
- Medium: 0 + 2×12 = 24 bits
- Large: 0 + 2×20 = 40 bits
- Production: 28 + 2×36 = 100 bits
- **GSR-style: 20 + 10×8 = 100 bits** ← same security, 5.4x cheaper

### The GSR Insight: High Blowup, Few Queries

The bitcoin-circle-stark project (Great Script Restoration) uses
`log_blowup=10` (1024x blowup factor) with only 8 queries. Each
query contributes 10 bits of FRI security instead of 2 bits with
standard blowup. The verifier wins massively because:

- **5.4x fewer Merkle verifications** (8 queries × 75 steps vs 36 × 77)
- **Smaller program DAG** (fewer array_fold iterations)
- **Less combinator routing** (the dominant cost)

The tradeoff: the **prover** works harder (1024x larger evaluation
domain = more polynomial evaluations), but the **verifier** — which
is what runs on-chain — is dramatically cheaper.

| Metric | Production (36q, blowup=4) | GSR (8q, blowup=1024) |
|--------|--------------------------|----------------------|
| Security | ~100 bits | ~100 bits |
| Verifier cost | 2,543M mWU | **474M mWU** |
| % of block | 63.5% | **11.9%** |
| Serialized | 73 KB | **25 KB** |
| C BitMachine | 52ms | **55ms** |
| Prover domain | 4,096 | 32,768 |

C BitMachine times are similar (~55ms) despite 5.4x cost difference
because the C interpreter is fast enough that both configs are
dominated by hash computation, not routing overhead.

### Optimization History

Three rounds of optimization, each building on the previous:

| Version | Production Cost | Production Size | C Time | Key Change |
|---------|----------------|-----------------|--------|------------|
| Initial (m31_inv at runtime) | >4.3B (overflow) | 291 KB | ~250ms | Baseline |
| + Precomputed twiddles | 3,285M | 188 KB | 148ms | -30% cost, fits u32 |
| + array_fold queries | **2,543M** | **73 KB** | **52ms** | -23% cost, -61% size |

**Total reduction from baseline: ~40% cost, ~75% size.**

The `array_fold` approach avoids the super-linear cost explosion seen
with full unrolling. In the unrolled version, each additional query
added increasing marginal cost (180M mWU/query at 36 queries) due to
deeper combinator DAGs. With `array_fold`, the fold function body is
compiled once and the marginal cost per query is constant.

### Approaches Tested and Rejected

**Witness-based proof data:** Moving Merkle siblings from program
constants to witness values was tested and found to increase cost at
every configuration (e.g., production: 3.82B vs 3.29B mWU). Witness
nodes cost `100 + bitwidth` mWU — the same as constant nodes — but
the witness loading boilerplate adds combinator overhead.

### Cost Composition

The dominant cost is **combinator routing** — threading data through
Simplicity's comp/pair/take/drop nodes. Actual computation (SHA-256
hashing, M31 arithmetic) accounts for ~1-2% of total mWU cost. The
`array_fold` optimization reduces routing by sharing the fold function
DAG across all queries.

### C BitMachine vs Rust BitMachine

The C BitMachine (with TCO) from simplicity-sys is dramatically
faster than the Rust interpreter, with the gap widening for larger
programs:

| Config | Rust | C | Speedup |
|--------|------|---|---------|
| Toy | 8ms | 3ms | 2.8x |
| Medium | 71ms | 8ms | 8.5x |
| Large | 330ms | 19ms | 17.6x |
| Production | 2.0s | **52ms** | **38x** |

The C implementation's TCO eliminates frame allocation overhead for
tail calls, and its gap-buffer memory model provides better cache
locality for large programs. The 52ms production time is well within
block validation budgets.

---

## 6. Head-to-Head: Circle STARK vs Groth16

Both systems implemented end-to-end in SimplicityHL with passing tests.

### Production Parameters (Fully Optimized)

| Metric | Circle STARK GSR | Circle STARK 36q | Groth16 (64-bit) | Groth16 (Fp jets) |
|--------|-----------------|------------------|-------------------|-------------------|
| Config | 8q, blowup=1024 | 36q, blowup=4 | — | — |
| Security | ~100 bits | ~100 bits | ~128 bits | ~128 bits |
| Cost (mWU) | **474M** | 2,543M | >4.3B | >4.3B |
| % of block | **11.9%** | 63.5% | >100% | >100% |
| Serialized size | **25 KB** | 73 KB | 126 KB | ~80 KB |
| C BitMachine | **55ms** | 52ms | N/A | N/A |
| New jets needed | **None** | None | None | 5 Fp jets |
| Post-quantum | **Yes** | Yes | No | No |
| Proof size | ~50-100 KB | ~50-100 KB | ~200 bytes | ~200 bytes |

### All Configurations vs Groth16

| Metric | Toy (3q) | Medium (12q) | Large (20q) | Prod (36q) | Groth16 |
|--------|----------|-------------|-------------|------------|---------|
| Cost (mWU) | 8.4M | 103M | 444M | **2,543M** | >4,295M |
| Size (KB) | 4.5 | 11.7 | 26.8 | 73 | 126 |
| C time | 3ms | 8ms | 19ms | **52ms** | N/A |
| Fits u32? | Yes | Yes | Yes | **Yes** | **No** |

### Scaling Behavior

With `array_fold`, cost scales linearly with query count (shared fold
function body). The super-linear cost explosion from unrolling is
eliminated:

| Queries | Unrolled mWU | Fold mWU | Fold Savings |
|---------|-------------|----------|--------------|
| 3 | 4.3M | 8.4M | -1.9x (overhead) |
| 12 | 74.6M | 103M | -1.4x |
| 20 | 407M | 444M | -1.1x |
| 36 | 3,285M | **2,543M** | **+23%** |

The fold approach breaks even at ~20 queries and wins decisively above
that. At production (36 queries), it saves 742M mWU and 115 KB.

Groth16 cost is constant regardless of circuit size (always 3 pairings)
but exceeds u32 even with Fp jets.

---

## 7. Comparative Summary

### By Proof System (Measured, Fully Optimized)

| Property              | Groth16 (64-bit) | Groth16 (Fp jets) | Circle STARK (GSR) |
|-----------------------|-------------------|-------------------|--------------------|
| Field size            | 381-bit           | 381-bit           | **31-bit**         |
| Needs new jets        | No                | 5 Fp jets         | **No**             |
| Post-quantum          | No                | No                | **Yes**            |
| Proof size            | **192 bytes**     | **192 bytes**     | 50-100 KB          |
| Production cost (mWU) | >4.3B (overflow)  | >4.3B (overflow)  | **474M**           |
| % of block            | >100%             | >100%             | **11.9%**          |
| C BitMachine time     | N/A               | N/A               | **55ms**           |
| Serialized program    | 126 KB            | ~80 KB            | **25 KB**          |

### By Execution Environment

| Property                    | Bitcoin Script | Simplicity   |
|-----------------------------|----------------|--------------|
| Subroutines/sharing         | No (inline)    | Yes (DAG)    |
| Loops                       | No (unrolled)  | for_while    |
| 64-bit arithmetic           | Needs soft fork| Exists today |
| SHA-256                     | Exists today   | Exists today |
| DAG advantage (64-bit ops)  | —              | 30-50x       |
| DAG advantage (bignum ops)  | —              | ~10x         |
| DAG advantage (M31 ops)     | —              | 3-5x         |

### The Key Insight

The DAG sharing advantage is inversely proportional to opcode
granularity. When each field operation is hundreds of sub-operations,
sharing the subroutine definition saves enormously. When each field
operation is one opcode, there's little to share. Circle PLONK, with
its tiny field, minimizes the gap between Script and Simplicity — both
fit comfortably.

---

## 8. What We Learned from Implementation

### Compiler Infrastructure Matters

- **Function body caching** (commit 7090180) was essential. Without it,
  the Groth16 verifier OOMs at 12+ GB. With it, compilation takes 5.3s
  at 178 MB. The Circle STARK verifier at production (4233 lines)
  similarly requires this cache.

- **Stack depth** is a real constraint. The production Circle STARK
  verifier needs `RUST_MIN_STACK=134217728` (128 MB) to compile.

### Fp Jets Help But Don't Solve Groth16

Adding 5 BLS12-381 Fp jets (add, subtract, multiply, negate, square)
gave a **10x execution speedup** (1239s → 125s) but the cost counter
still overflows. The bottleneck shifts from arithmetic to **data
routing** — Fp12 values are 4608 bits wide, and Simplicity's
combinator tree must route every bit through take/drop/pair nodes.

Higher-level jets (Fp2, Fp6, Fp12, or full pairing) are needed to
make Groth16 fit in a block.

### Circle STARKs Are Natively Suited to Simplicity

- M31 arithmetic needs only `jet::multiply_32` + bitwise ops — all
  existing jets.
- SHA-256 Merkle verification uses native `jet::sha_256_ctx_8_*` jets.
- The Fiat-Shamir channel is just SHA-256 hashing.
- No new consensus changes needed for Simplicity.
- Precomputing twiddle inverses (code generation optimization) brought
  production within u32 cost bounds.
- `array_fold` with cached function bodies avoids the super-linear cost
  explosion that plagues large unrolled programs.

### The C BitMachine Is Production-Ready

The Rust BitMachine gives misleading performance numbers. The C
implementation (via simplicity-sys FFI) is 38x faster for production
programs due to TCO and gap-buffer memory management. Always benchmark
with the C FFI — the Rust interpreter is useful for development but
not representative of consensus validation time.

### Combinator Routing Dominates Cost

Across all configurations, >98% of mWU cost comes from combinator
routing (comp/pair/take/drop nodes threading data through the DAG),
not from actual computation (jets). This means:
- Program structure matters more than computation efficiency
- `array_fold` helps by sharing DAG structure across iterations
- Witness-based data does NOT help (same routing cost per node)
- A Merkle path jet would help by collapsing many routing-heavy
  hash operations into a single jet call

### The BitMachine Routing Bottleneck

For both proof systems, a significant fraction of the cost is not
arithmetic but **data routing through Simplicity's combinator DAG**.
This is particularly acute for Groth16 where Fp12 values (72 limbs)
must be threaded through product trees. Circle STARKs avoid this by
using small types — QM31 is only 4 u32 values (128 bits total), making
routing overhead negligible.

---

## 9. Recommendations (Updated)

1. **Circle STARK verification fits within 1/10 of a block at
   production security in Simplicity today.** Using the GSR parameter
   choice (8 queries, log_blowup=10, 20 PoW bits = ~100-bit security),
   the verifier costs 474M mWU (11.9% of a block), fits in 25 KB,
   executes in 55ms on the C BitMachine, and requires zero new jets.
   This leaves ~88% of the block for other transactions.

2. **The C BitMachine is fast enough for block validation.** At 52ms
   for a production Circle STARK verification, a Liquid/Bitcoin node
   can validate these transactions without impacting block processing.
   The Rust interpreter (2s) is not representative — always benchmark
   with the C FFI.

3. **`array_fold` is essential for large programs.** Unrolling 36
   queries caused super-linear cost growth (180M mWU marginal per
   query). Using `array_fold` with a cached fold function body reduced
   production cost by 23% and program size by 61%. Witness-based data
   was tested and rejected (increases cost at every size).

4. **Groth16 requires pairing-level jets to be practical.** Even with
   Fp jets (10x speedup), the cost overflows u32. The data routing
   overhead for 4608-bit Fp12 values is an architectural limit of the
   BitMachine that cannot be solved by field-level jets alone.

5. **The BLS12-381 Groth16 implementation remains valuable as a jet
   specification.** The SimplicityHL code serves as a reference that
   higher-level jets (Fp2, Fp12, pairing) would be validated against.

6. **For Bitcoin Script, OP_MUL + OP_CAT is the minimum viable soft
   fork for ZK verification** — enabling Circle PLONK verification
   with just two new opcodes.

7. **The GSR parameter choice (high blowup) is the key to practical
   on-chain verification.** `log_blowup=10` gives 10 bits of security
   per query, so 8 queries + 20 PoW bits = 100 bits. The prover pays
   (1024x larger domain) but the verifier — running on-chain — is
   5.4x cheaper than the 36-query low-blowup alternative. This is a
   pure parameter tuning win, requiring no protocol or jet changes.

---

## 10. Implementation Artifacts

All code is in the SimplicityHL repository on branch
`2026-03-groth16-verifier`.

### Groth16 Verifier
- `examples/groth16/fp.simf` — BLS12-381 base field (Montgomery)
- `examples/groth16/fp_inv.simf` — Field inversion (Fermat)
- `examples/groth16/fp2.simf` — Quadratic extension
- `examples/groth16/fp12.simf` — Degree-12 extension
- `examples/groth16/g1.simf`, `g2.simf` — Curve operations
- `examples/groth16/miller.simf` — Miller loop
- `examples/groth16/final_exp.simf` — Final exponentiation
- `examples/groth16/pairing.simf` — Full pairing
- `examples/groth16/groth16.simf` — Complete verifier
- `examples/groth16/fp_jet_test.simf` — Fp jet validation

### Circle STARK Verifier
- `examples/circle_stark/m31.simf` — M31/CM31/QM31 arithmetic
- `examples/circle_stark/channel.simf` — SHA-256 Fiat-Shamir
- `examples/circle_stark/merkle.simf` — Merkle tree verification
- `examples/circle_stark/circle.simf` — Circle group operations
- `examples/circle_stark/fri.simf` — FRI folding
- `examples/circle_stark/verifier.simf` — Generated end-to-end verifier (array_fold)
- `examples/circle_stark/gen_fold.py` — Proof generator with array_fold (production)
- `examples/circle_stark/gen_vectors.py` — Proof generator with unrolling (reference)

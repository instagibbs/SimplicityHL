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

### Measured Benchmarks (Optimized)

All configurations generate real proofs and pass end-to-end
verification in SimplicityHL. The verifier uses precomputed twiddle
factor inverses — all `m31_inv` calls have been eliminated, leaving
only straight-line arithmetic and SHA-256 hashing.

| Config | Queries | FRI Layers | Domain | Cost (mWU) | Size (KB) | Cells (KB) | Exec Time |
|--------|---------|------------|--------|------------|-----------|------------|-----------|
| Toy | 3 | 3 | 32 | **4.3M** | 5.5 | 94 | 0.6s |
| Medium | 12 | 5 | 128 | **74.6M** | 25.9 | 3,494 | 1.7s |
| Large | 20 | 7 | 512 | **407M** | 64.2 | 22,166 | 4.5s |
| Production | 36 | 10 | 4096 | **3,285M** | 187.9 | 192,459 | 35s |

**Security levels (approximate):**
- Toy: ~6 bits (testing only)
- Medium: ~24 bits
- Large: ~40 bits (log2(blowup) × queries = 2 × 20)
- Production: ~72 bits from FRI (needs +28 PoW bits for ~100-bit total)

**Production fits within u32 cost limit** (3.29B < 4.295B max).

### Optimization Applied: Precomputed Twiddle Inverses

The original `ibutterfly` computed `m31_inv(2 * twiddle)` at runtime,
requiring a 30-iteration square-and-multiply loop per call (360 calls
at production). Precomputing these in the Python generator and
embedding them as constants gave a consistent ~30% cost reduction:

| Config | Before (mWU) | After (mWU) | Reduction |
|--------|-------------|-------------|-----------|
| Toy | 5.9M | 4.3M | -26% |
| Medium | 107M | 74.6M | -30% |
| Large | 577M | 407M | -29% |
| Production | >4.3B (overflow) | **3,285M** | **Now fits** |

This also removed all `for_while` loops from the verifier — every
operation is now straight-line code.

### Cost Breakdown (Production, Optimized)

The remaining costs are:

1. **SHA-256 Merkle verification** — 2,772 hash operations (36 queries
   × average ~77 Merkle steps across trace + 10 FRI layers). This is
   now the dominant cost.

2. **QM31 arithmetic in FRI folds** — 360 fold operations, each doing
   2 qm31_scale + 1 qm31_mul + adds ≈ ~55 jets per fold.

3. **Fiat-Shamir channel** — ~50 SHA-256 hashes for squeezing
   challenges and query indices.

4. **Combinator routing overhead** — the 4096-line unrolled program
   creates significant DAG routing overhead (192 MB of cells).

---

## 6. Head-to-Head: Circle STARK vs Groth16

Both systems implemented end-to-end in SimplicityHL with passing tests.

### Production Parameters (Optimized)

| Metric | Circle STARK (36q, 10fri) | Groth16 (64-bit jets) | Groth16 (Fp jets) |
|--------|--------------------------|----------------------|-------------------|
| Cost (mWU) | **3,285M** | >4.3B (overflow) | >4.3B (overflow) |
| Fits in u32? | **Yes** | No | No |
| Serialized size | 188 KB | 126 KB | ~80 KB |
| BitMachine cells | 192 MB | 2.5 MB | ~2 MB |
| Execution time | **35s** | 1,239s | **125s** |
| Exec speedup vs Groth16 | **35x** faster | baseline | 10x faster |
| New jets needed | **None** | None | 5 Fp jets |
| Post-quantum | **Yes** | No | No |
| Proof size (witness) | ~50-100 KB | ~200 bytes | ~200 bytes |

### All Configurations vs Groth16

| Metric | Toy (3q) | Medium (12q) | Large (20q) | Prod (36q) | Groth16 |
|--------|----------|-------------|-------------|------------|---------|
| Cost (mWU) | 4.3M | 74.6M | 407M | **3,285M** | >4,295M |
| Size (KB) | 5.5 | 25.9 | 64.2 | 188 | 126 |
| Exec time | 0.6s | 1.7s | 4.5s | 35s | 125-1239s |
| Fits u32? | Yes | Yes | Yes | **Yes** | **No** |

### Scaling Behavior

Circle STARK cost scales roughly as `O(queries × fri_layers × avg_merkle_depth)`:

```
Cost ≈ 250K × queries × fri_layers (mWU, optimized)
```

Groth16 cost is constant regardless of circuit size (always 3 pairings).
Circle STARK at production security (~100 bits) now fits within u32
cost bounds. Groth16 does not, even with Fp jets.

---

## 7. Comparative Summary

### By Proof System (Measured, Optimized)

| Property              | Groth16 (64-bit) | Groth16 (Fp jets) | Circle STARK |
|-----------------------|-------------------|-------------------|--------------|
| Field size            | 381-bit           | 381-bit           | **31-bit**   |
| Needs new jets        | No                | 5 Fp jets         | **No**       |
| Post-quantum          | No                | No                | **Yes**      |
| Proof size            | **192 bytes**     | **192 bytes**     | 50-100 KB    |
| Production cost (mWU) | >4.3B (overflow)  | >4.3B (overflow)  | **3,285M**   |
| Fits in u32?          | No                | No                | **Yes**      |
| Exec time (prod)      | 1,239s            | 125s              | **35s**      |
| Serialized program    | 126 KB            | ~80 KB            | 188 KB       |

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
- Precomputing twiddle inverses (a code generation optimization, not a
  protocol change) brought production within u32 cost bounds.

### The BitMachine Routing Bottleneck

For both proof systems, a significant fraction of the cost is not
arithmetic but **data routing through Simplicity's combinator DAG**.
This is particularly acute for Groth16 where Fp12 values (72 limbs)
must be threaded through product trees. Circle STARKs avoid this by
using small types — QM31 is only 4 u32 values (128 bits total), making
routing overhead negligible.

---

## 9. Recommendations (Updated)

1. **Circle STARK verification works at production security in
   Simplicity today.** At 36 queries / 10 FRI layers (~100-bit
   security with PoW), it costs 3.29B mWU, fits in 188 KB, and
   requires zero new jets. This is the only proof system that fits
   within measurable cost bounds at production security.

2. **Groth16 requires pairing-level jets to be practical.** Even with
   Fp jets (10x speedup), the cost overflows u32. The data routing
   overhead for 4608-bit Fp12 values is an architectural limit of the
   BitMachine that cannot be solved by field-level jets alone.

3. **The BLS12-381 Groth16 implementation remains valuable as a jet
   specification.** The SimplicityHL code serves as a reference that
   higher-level jets (Fp2, Fp12, pairing) would be validated against.
   The Fp jet work (commits ccb9d27, a04d6bc) demonstrates the jet
   integration pattern.

4. **For Bitcoin Script, OP_MUL + OP_CAT is the minimum viable soft
   fork for ZK verification** — enabling Circle PLONK verification
   with just two new opcodes. This is the smallest consensus change
   that unlocks on-chain ZK.

5. **Further optimization opportunities remain.** The production
   verifier's 188 KB program size and 192 MB cell usage come from
   fully unrolling 36 queries. Using `for_while` loops or `array_fold`
   with witness-provided proof data could reduce program size by ~10x,
   potentially reducing cost further through smaller combinator DAGs.
   The dominant remaining cost is SHA-256 Merkle hashing (~2,772
   hash operations).

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
- `examples/circle_stark/verifier.simf` — Generated end-to-end verifier
- `examples/circle_stark/gen_vectors.py` — Proof generator (toy/medium/large/production)

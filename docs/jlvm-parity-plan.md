# Cross-Language Parity & Packaging Roadmap

> **Status (2026-07-16).** Supersedes the prior "JLVM lives in Rust + TS only;
> Go/Java/Python are signing-only *by design*" note. That design decision is
> **reversed**: the goal is now **full byte-for-byte JLVM parity across all five
> client languages**, plus a **uniform 3-tier package delineation** (core / std /
> jlvm) in every language. This doc is the plan of record.

## Goal

1. **Byte-for-byte parity** of Go, Java, and Python with the Scala reference
   (`metakit`) and the two already-complete ports (Rust, TypeScript) — the whole
   JLVM surface: evaluator, gas, crypto opcodes, proof verifiers, Poseidon.
2. **Uniform packaging**: every language ships three artifacts, named off the base
   package — the only suffixes are `-core` and `-jlvm`; the middle "batteries-included"
   tier is the **unsuffixed base name** (there is no `-std`), matching TS
   (`@constellation-network/metagraph-sdk-core` / `…/metagraph-sdk` / `…/metagraph-sdk-jlvm`).
   - **`<base>-core`** — the fully-offline kernel: JCS canonicalization + `dropNulls`,
     `JsonBinaryHasher` content-hash, binary codec, committed-roots light-client
     codecs, **AND signing** (sign / verify / signed-object / wallet + low-level
     crypto). Signing is offline, so it lives here. *No network, no currency-tx
     layer.* This is exactly what `packages/typescript-core` ships.
   - **`<base>`** (base name, no suffix) — depends on and re-exports core, then adds
     the currency/data-tx layer and the network client. The batteries-included
     package (`packages/typescript`, `packages/rust`).
   - **`<base>-jlvm`** — the extension: evaluator + gas + all crypto/ZK opcodes +
     Poseidon + MPT/SMT/PMT verifiers + numerics. Depends on core.

Scala (`metakit`) is the reference. The **`shared/*.json` conformance vectors are
the byte-exact contract**: a port is "at parity" iff it reproduces every vector.

## Current state

| Surface | Scala (ref) | Rust | TS | Go | Java | Python |
|---|---|---|---|---|---|---|
| A. Canonicalization (JCS + dropNulls) | ✅ | ✅ | ✅ | ✅ | ✅ | ⚠️¹ |
| B1. Content hash (JsonBinaryHasher) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| B2. Poseidon-BN254 | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| B3. secp256k1 signing / currency-tx | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| C. JLVM evaluator (87 ops) + gas | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| D. Crypto opcodes² | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| E. Proof structures (MPT/SMT/PMT) | ✅ | ✅ | ✅ | ❌ | ❌ | ❌ |
| F. Conformance vectors loaded | 6/6 | 6/6 | 6/6 | 2/6 | 2/6 | 2/6 |

¹ Python `dropNulls` + JCS key-order are correct, but the `rfc8785` PyPI lib throws
on integers ≥ 2⁵³ — unusable for JLVM values; a hand-rolled canonical-json is required.
² `groth16_verify`, `sigma_verify` (+`prove_dlog`/`prove_dhtuple`, CDS AND/OR/THRESHOLD),
`schnorr_verify`, `bls_verify`/`bls_aggregate_verify`, `ecvrf_verify`,
`bn254_add`/`mul`/`pairing`, `poseidon`, `pmt_verify`, `smt_verify`, `mpt_verify`,
`mpt_prefix_verify`.

**Go, Java, Python are complete `core`+`std` ports and 0% of the JLVM tier.** Each
needs a body of work comparable to `typescript-jlvm` / `rust/jlvm-core` (~10k LOC).
Java is additionally version-skewed (`0.1.0` vs the `1.8.0-rc.x` line) and never
published to Maven Central.

## The byte-parity contract (`shared/*.json`)

| File | Surface | Cases |
|---|---|---|
| `json_logic_test_vectors.json` | JLVM evaluator | 23 categories / 166 |
| `zk_opcode_test_vectors.json` | crypto + auth-DB opcodes | 17 categories / 156 |
| `gas_test_vectors.json` | gas meter (Default profile) | 12 categories |
| `ordinal_catalog_test_vectors.json` | committed-state attestation (SMT + epoch-MPT) | 10 |
| `test_vectors.json` | canonicalize + hash + sign KATs | 16 |
| `currency_transaction_vectors.json` | currency-tx signing (SDK-only) | — |

Sync is **manual file-copy** metakit ⇄ `shared/`, with **no cross-repo CI gate**
today — this already caused a drift (metakit `zk_opcode` v1.12.0 vs SDK v1.13.0).

### The most load-bearing byte rules (hand these to every porter)

1. Content-hash pre-image field order is **RFC-8785 sorted keys**, not struct order.
2. `dropNulls` **before** JCS on every typed-content hash — drop object nulls,
   **keep array nulls**.
3. 1-byte type prefixes prepended to JCS bytes: MPT Leaf/Branch/Ext = `0x00/0x01/0x02`,
   SMT Leaf/Internal = `0x00/0x01`; MPT `dataDigest` has **no** prefix.
4. MPT `path`/`remaining`/`shared` = **one hex char per nibble**.
5. SMT `position = sha256(UTF-8 of the key's hex string, undecoded)`.
6. SMT bit order **MSB-first**, PMT bit order **LSB-first**.
7. JLVM ints = unbounded BigInt, floats = **exact Ratio**; rounding only at
   serialization (Ryu shortest-double) and the DECIMAL128 `cat`/`join`/`in` path.
8. **String indexing is UTF-16 code units** (a hazard for Go byte-strings and Python
   code-point strings); lone surrogates → U+FFFD.
9. Sigma challenges are **31 bytes** (injective into Fr) with a frozen tag-byte transcript.

## Sequencing (decided)

**Contract-first, then Go pilot → Java → Python.**

### Phase 1 — Contract (language-agnostic; make the oracle complete & drift-proof)

- **C1. Vector drift reconciliation** — ✅ metakit#61 (sync `zk_opcode` to v1.13.0).
- **C2. Cross-repo parity CI gate** — pinned-ref byte-diff: metakit CI checks out the
  SDK `shared/` at a pinned SHA (a `.metakit-sdk-ref` file bumped alongside re-vendors)
  and `sha256`-diffs the 5 vendored vector files; a soft non-blocking reminder in SDK
  CI on `shared/**` changes. **Needs a read-only cross-repo token (user action).**
- **C3. MPT absence for clients** — PR #60 added sealed `Inclusion|Absence` to the
  **committed-state layer** (`Committed.proveKey`), *not* the `mpt_verify` opcode
  (inclusion-only by design). No SDK port verifies absence yet. Add a light-client
  sealed-proof verifier to Rust + TS (mirroring ottochain-sdk's `verifyMptAbsence`) +
  vectors, so the client libs catch up to the server on the one feature it's ahead on.

### Phase 2 — Packaging tiers (do before porting, so JLVM lands in the right package)

1. Write the **tier-boundary spec** (exact symbol → core/std/jlvm map + the
   core←std, core←jlvm edges). Reference: `docs/package-tiers.md`.
2. **TS is the reference 3-package model** — do NOT restructure it: `metagraph-sdk-core`
   is the offline kernel *including signing*, `metagraph-sdk` (base) re-exports core +
   currency + network, `metagraph-sdk-jlvm` is the extension. **Rust is being split to
   match it**: carve a new `constellation-metagraph-sdk-core` crate (offline kernel,
   signing included) out of the fused `packages/rust`; the base `constellation-metagraph-sdk`
   crate re-exports it so all existing `constellation_sdk::*` paths are unchanged, and
   keeps currency + `network`/`r1` features; `rust/jlvm-core` + `rust/poseidon-bn254`
   remain the JLVM tier. *(Safe now — no external consumers yet.)*
3. **Restructure Go/Java/Python to MATCH that boundary**: `<base>-core` = offline
   kernel **including signing** (canonicalize/binary/codec/hash/committed-roots +
   sign/verify/signed-object/wallet); the unsuffixed base package = core + currency +
   network; plus an **empty `<base>-jlvm` placeholder** so the later port is purely
   additive. The middle tier is the base name — NOT `-std`.
4. **Unify the release train**: bump Java `0.1.0`→`1.8.0-rc.x`, wire Java into
   `release.yml` (Maven job on the `v*` tag), extend the `version-check` gate to the new
   artifacts; Go stays on its path-tag at the same version.

### Phase 3 — JLVM ports (Go pilot → Java → Python), each layered & vector-gated

Per language, dependency-ordered (each layer's acceptance = its vector suite green):

1. **Canonicalization for the JLVM value space** — big-int/ratio-aware JCS (NOT the
   generic RFC-8785 libs, which clamp/throw on large ints). *(json_logic vectors)*
2. **Arbitrary-precision numerics** — BigInt + exact Ratio. Go: `math/big` (mind
   auto-reduction). Java: `BigInteger` + `BigFraction`. Python: native `int` +
   `fractions.Fraction` (cheap win — verify reduction/sign parity).
3. **JLVM evaluator + 87 ops + gas meter** (the largest item). *(json_logic + gas vectors)*
4. **Poseidon-BN254** — hand-ported constants/MDS/permutation. *(poseidon KATs)*
5. **Crypto opcodes** — groth16 / sigma family / schnorr / bls / ecvrf / bn254 /
   pmt / smt / mpt / mpt_prefix. Reuse curve/pairing libs (Go `gnark-crypto`+`btcec`;
   Java web3j alt-bn128 or arkworks-JNI + BC; Python `py_ecc`), hand-write Poseidon +
   sigma transcripts + proof verifiers. *(zk_opcode vectors)*
6. **Proof structures** — MPT/SMT/PMT verifiers. *(zk_opcode + ordinal_catalog vectors)*
7. **Vector wiring** — differential runners for all 6 shared sets.

**Go first** as the pilot (best crypto-lib ecosystem: `gnark-crypto`, `btcec`) to prove
the layered approach and shake out any vector issues, then replicate the proven pattern
to **Java** and **Python**.

## Per-language hazards (byte-parity traps)

- **Go** — `big.Rat` auto-reduces (must match reference Ratio); byte-string indexing
  vs UTF-16 rule; Poseidon constants have no drop-in (gnark's poseidon2 ≠ circomlib);
  Groth16 must match the SP1 verifier pre-image, not gnark's generic verifier.
- **Java** — `double` currency path is a precision hazard; needs `BigInteger`+exact
  rational; JCS lib (`erdtman`) is double-based → disqualified for JLVM canonicalization;
  BN254/pairing lib choice (web3j pure-Java vs arkworks-JNI) is the big architectural call.
- **Python** — `rfc8785` throws on ints ≥ 2⁵³ (hard blocker → hand-roll JCS);
  code-point vs UTF-16 string indexing; `py_ecc` covers BN254/BLS pairing but encodings
  must be byte-matched.

## Delegation / parallelization

- The three ports are **independent** → separate tracks (Go pilots the pattern).
- Within a language, layers 1–2 are the sequential foundation; Poseidon (4) is
  independent of the evaluator (3); crypto (5) and proofs (6) follow Poseidon.
- Each layer is a self-contained, **vector-gated** unit of work — ideal for delegation:
  an agent ports a layer and must make its differential suite green.
- The `shared/*.json` oracle makes every port mechanically verifiable — the saving
  grace that makes a ~10k-LOC crypto port tractable via subagents.

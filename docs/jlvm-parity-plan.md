# JLVM Cross-Language Parity Plan

## Scope (confirmed 2026-06-06)
- **TypeScript:** base JLVM only — no ZK opcodes. (Already runs the shared base vectors.)
- **Scala ↔ Rust:** FULL parity — base JLVM **and** the entire zk-JLVM: all ZK opcodes + full auth-DB (Sparse Merkle + Merkle Patricia) in Rust.

## Principle
Scala (metakit) is the reference. Formal **shared vectors** live in `shared/` — known-answer where they exist, Scala-generated for coverage — and Rust must reproduce every one byte-for-byte (the discipline that already governs the 59 base vectors via `rust/jlvm-core/tests/differential.rs`).

## Rust opcode surface to reach parity
`poseidon` · `pmt_verify` · `smt_verify` · `mpt_verify` · `mpt_prefix_verify` · `groth16_verify` · `ecvrf_verify` · `bn254_add`/`mul`/`pairing` · `bls_verify`/`bls_aggregate_verify` · `schnorr_verify`

Rust already has `poseidon-bn254`, the fixed-depth Poseidon Merkle (from the shielded transfer), and `canonical.rs`.

## Per-tier loop
generate vectors (from Scala) → implement in Rust → run vectors → **adversarial byte-identity audit vs Scala** → review → next tier.

- **Phase 0 — Vectors:** all ZK/auth-db opcode vectors from Scala + known-answer values (poseidon `0x115cc0f5…`, RFC-9381 VRF, EIP-197 pairing identity, the real SP1 groth16 fixture) → `shared/zk_opcode_test_vectors.json`.
- **Tier 1 (low risk):** `poseidon`, `pmt_verify`, `schnorr_verify`.
- **Tier 2 (medium):** `smt_verify`, `mpt_verify`, `mpt_prefix_verify`, `bn254_add/mul/pairing`, `ecvrf_verify`.
- **Tier 3 (high):** `groth16_verify`, `bls_verify`/`bls_aggregate_verify`.

## BLS ciphersuite (Tier 3) — DECIDED
Abandon MIRACL's SVDW; adopt the standard **eth2 SSWU** ciphersuite (`BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_`). Scala via **Bouncy Castle 1.85** (pre-release, supports SSWU); Rust via blst/arkworks (native). Interoperable + standard. Re-does wave-2's `bls_verify`/`aggregate`.

## Base-parity follow-ups (found by the Scala conformance runner)
Scala trails Rust/TS on two base operators the shared vectors exercise: **3-arg `get`** `[map,key,default]` and **object-form `let`** `{let:[{name:expr},result]}`. Extend Scala to match (small), or trim vectors. Tracked as guarded xfails in metakit `SharedVectorConformanceSuite`.

## Execution
Per-tier orchestrated multi-agent workflows; review the vectors + each tier's audit before starting the next tier.

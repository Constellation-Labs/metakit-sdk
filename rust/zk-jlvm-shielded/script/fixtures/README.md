# zk-jlvm-shielded (M5) groth16 fixtures

`transition_groth16_fixture.json` is a **committed SP1 Groth16 proof bundle**
(`vkey` + `publicValues` + `proof`) for the M5 private-state-transition circuit.
The verify-side tests / zk e2e check a real proof against this fixture so they
stay cheap and CI-friendly (no GPU proving in CI).

## When you MUST regenerate it

The fixture's `vkey` is derived from the **compiled guest ELF**
(`rust/zk-jlvm-shielded/program`). Anything that changes that ELF rotates the
VKEY and makes the committed fixture stale. Regenerate when you change:

- **The JLVM evaluator — `rust/jlvm-core`.** The M5 guest runs the JLVM
  *effect* evaluator, so **adding / removing / renaming an opcode, changing an
  opcode's semantics, or changing gas** all change the guest ELF → VKEY — **even
  if the M5 test scenario doesn't *use* the new opcode** (the dispatch arm is
  still compiled in). _(This is exactly why adding `set` / `unset` / `hex_to_int`
  required a regen.)_
- **The M5 circuit itself** — `rust/zk-jlvm-shielded/{lib,program}` (commitment /
  nullifier / transition constraints, public-values layout).
- **A dependency that changes the guest's compiled code** — `poseidon-bn254`,
  the SP1 zkVM (`sp1-zkvm`) version, or the Rust toolchain.

You do **not** need to regenerate for: host/`script` changes, Scala/TS evaluator
changes (the guest is Rust), docs, or `zk-shielded` (M4) changes (a separate
circuit with no `jlvm-core` dependency — see
`../../../zk-shielded/script/fixtures/README.md`).

## CI does not catch staleness

CI tests the constraint **libs** only; it does **not** run the SP1 prover (no
SP1/GPU toolchain). A stale VKEY surfaces only when the real groth16 e2e runs,
so keeping this fixture fresh is a **manual discipline** — do it in the same PR
(or a fast follow-up) as the triggering change.

## How to regenerate (GPU)

```bash
cd rust/zk-jlvm-shielded/script
SP1_PROVER=cuda RUST_LOG=warn cargo run --release -- --mode groth16
```

Rebuilds the guest, derives the fresh VKEY, generates + verifies the proof, and
overwrites `fixtures/transition_groth16_fixture.json`. ~1–3 min on an NVIDIA GPU.
The host crate's `sp1-sdk` already carries the `cuda` feature; **without
`SP1_PROVER=cuda` it silently proves on CPU** (many minutes). Commit the updated
fixture. See the repo's `sp1-gpu-proving` workflow for the GPU gotchas.

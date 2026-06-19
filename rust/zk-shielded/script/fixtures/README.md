# zk-shielded (M4) groth16 fixtures

`shielded_groth16_fixture.json` is a committed SP1 Groth16 proof bundle
(`vkey` + `publicValues` + `proof`) for the M4 confidential-transfer circuit.

## When to regenerate

The M4 guest (`rust/zk-shielded/program`) is **Poseidon-only and does NOT depend
on `jlvm-core`** — so **JLVM opcode / semantics / gas changes do NOT affect this
fixture.** Regenerate only when the M4 guest ELF itself changes:

- the M4 circuit — `rust/zk-shielded/{lib,program}`
- `poseidon-bn254`, the SP1 zkVM (`sp1-zkvm`) version, or the Rust toolchain

```bash
cd rust/zk-shielded/script
SP1_PROVER=cuda RUST_LOG=warn cargo run --release -- --mode groth16
```

Contrast with the **M5** circuit (`zk-jlvm-shielded`), which DOES run the JLVM
evaluator and therefore must be regenerated on opcode/semantics changes — see
`../../../zk-jlvm-shielded/script/fixtures/README.md`.

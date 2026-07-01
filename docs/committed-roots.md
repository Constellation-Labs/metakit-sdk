# Committed-roots light-client verification

This documents the committed-roots surface ported to the TypeScript and Rust
SDKs (`@constellation-network/metagraph-sdk-core` `committed-roots.ts`,
`constellation-metagraph-sdk` `committed_roots.rs`). It is byte-for-byte aligned
with the metakit (Scala) reference in
`io.constellationnetwork.metagraph_sdk.lifecycle.committed` and verified by the
same known-answer values as Scala's `CommittedRootsCodecKatSuite`.

## What it is

A metagraph commits a **two-tier state root** at every snapshot:

- **tier 1 — `mptRoot`**: the state-dict Merkle-Patricia root (current state).
- **tier 2 — `catalogRoot`**: the live catalog root — a full-history rollup of
  every committed MPT root (a Sparse Merkle root).

These are bound into one **`CommittedBreadcrumb`** committed at one ordinal. The
breadcrumb is *constant size* and never accumulates: because each per-step
transition was validated by the then-current validators, the latest signed
breadcrumb transitively commits the whole history (the Ethereum-header model). A
freshly syncing light client obtains the consensus-attested catalog root in O(1)
without replaying history.

## Wire formats (byte-exact)

Matching the Scala circe codecs exactly:

| Type | JSON |
|---|---|
| `SparseMerkleRoot` | `{"value":"<hash-hex>"}` |
| `CommittedRoots` | `{"mptRoot":"<hash-hex>","catalogRoot":{"value":"<hash-hex>"}}` |
| `CommittedBreadcrumb` | `{"ordinal":<number>,"roots":<CommittedRoots>}` |
| `CommitKey` | a bare validated string, e.g. `"fiber/abc-1"` |

- `mptRoot` is a **bare hash hex** (Scala `Hash`).
- `catalogRoot` is a **`SparseMerkleRoot` object** (`{"value":…}`).
- `ordinal` is a **bare non-negative integer** — Scala `SnapshotOrdinal`, whose
  encoder is `Encoder[NonNegLong].contramap(_.value)` (confirmed against the
  tessellation-sdk 4.0.0 bytecode; it is *not* wrapped in `{"value":…}`).

Key order is significant and preserved (`[mptRoot, catalogRoot]`,
`[ordinal, roots]`) so a re-encode reproduces the reference `noSpaces` bytes.

## `combinedHash`

```
combinedHash = sha256( rawBytes(mptRoot) ++ rawBytes(catalogRoot) )   // mpt first
```

Both roots contribute their 32 raw digest bytes (hex-decoded), mpt first — 64
bytes total. This is exactly what a snapshot's on-chain calculated-state proof
anchors (`hashCalculatedState`). Known-answer (both roots the KAT fixtures
`0xaa*32` and `0xbb*32`):

```
sha256(aa*32 ++ bb*32) = e2d80f78d79027556d6619a1400605abbdca6bb6eb24e0831e33ecd5466fa5f6
```

## `CommitKey`

A validated, namespaced path into the committed state dictionary (the MPT key
universe):

- `key = segment *( "/" segment )`, 1..16 segments, total ≤ 256 chars.
- `segment = [a-z0-9] [a-z0-9._-]{0,63}` (lowercase only, no empty segments, no
  leading/trailing `/`).
- **MPT path** = `toHex(key)` = lowercase hex of the key's UTF-8 bytes. Because
  `/` is a single byte (`0x2f`), the hex of `"ns/"` is a strict prefix of every
  key under namespace `ns` — which is what makes namespace prefix proofs work.

## Light-client verification flow

1. **Obtain** the latest signed `CommittedBreadcrumb` (from the snapshot's
   on-chain state) and **decode** it.
2. **Anchor**: verify the snapshot signature (signing SDK), then check
   `committedRootsCombinedHash(breadcrumb.roots)` equals the snapshot's
   `calculatedStateHash`. The trusted `catalogRoot` / `mptRoot` now follow from
   the consensus-attested snapshot.
3. **Prove membership** against those trusted roots with the JLVM opcodes:
   `mpt_verify` / `mpt_prefix_verify` for state-dict keys (derive the path with
   `CommitKey.toHex`), `smt_verify` for catalog-root inclusion. These already
   ship in `@constellation-network/metagraph-sdk-jlvm` and
   `constellation-metagraph-sdk-jlvm`.
4. **Attest an ordinal** (`ordinal → committed MPT root`) against the trusted
   catalog root with `verifyOrdinalCatalogProof(catalogRoot, proof, epochSize)`
   (see below).

## Ordinal-catalog attestation

`verifyOrdinalCatalogProof` (TS `ordinal-catalog.ts`, Rust `ordinal_catalog.rs`,
in the **JLVM** packages, where the SMT verifier lives) answers "was an MPT root
committed at snapshot ordinal N, and if so which one?" against a trusted catalog
root. It returns `CommittedAt{ordinal, mptRoot}`, `NotCommitted{ordinal}`, or a
verification error (`WrongProofKey` / `ProofInvalid` / `MalformedOrdinalProof`,
at component granularity).

The proof is a two-tier epoch rollup: the TOP catalog surfaces the hot-epoch and
level-1 (sealed) roots; a hot ordinal is one SMT inclusion, an ancient ordinal is
two fixed-depth inclusions (level-1 → sealed epoch tree), non-membership is
absence at both levels. Every catalog SMT key is recomputed **locally** from
`ordinal` and the chain-wide `epochSize` as `lowercaseHex(sha256(utf8(name)))`
(names: `epoch:hot`, `epoch:sealed`, `ordinal:<N>`, `epoch:<E>` — integers are
plain decimal), so a prover cannot prove absence in the wrong epoch tree.
`epochSize` is consensus-critical and MUST come from config, never the proof.

Conformance is proven byte-for-byte against
`shared/ordinal_catalog_test_vectors.json` (generated by the Scala
`OrdinalCatalogVectorGenerator`) — covering hot / sealed / epoch-boundary /
absent ordinals and tampered-proof negatives.

## Scope / deferred

Everything a roots-only light client needs is ported: the commitment codecs
(`CommittedRoots`, `CommittedBreadcrumb`, `CommitKey`, `combinedHash`) and the
full `OrdinalCatalogProof` attestation. Not ported (node-side only): proof
*serving* (`EpochCatalog.proveOrdinal`, catalog hydration/retention) — the SDK
verifies attestations, it does not produce them.

## References

- Scala: `src/main/scala/io/constellationnetwork/metagraph_sdk/lifecycle/committed/{CommittedRoots,CommitKey,OrdinalCatalogProof}.scala`
- Scala KAT: `src/test/scala/lifecycle/committed/CommittedRootsCodecKatSuite.scala`
- TS: `packages/typescript-core/src/committed-roots.ts` (+ `tests/committed-roots.test.ts`)
- Rust: `packages/rust/src/committed_roots.rs`

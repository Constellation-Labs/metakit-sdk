# metagraph-sdk-jlvm

**Reserved placeholder module — no real source yet.**

This module is a placeholder for the future Java port of the JLVM
(the metakit evaluator, crypto opcodes, and proof/verification port).
It currently ships no classes and builds an empty artifact so that the
`metagraph-sdk-jlvm` coordinate is reserved and the reactor layout mirrors
the `core` / `std` / `jlvm` split used by the other language SDKs.

When the JLVM port lands, its sources will live here under
`src/main/java/io/constellationnetwork/metagraph/sdk/jlvm/` and this module
will depend on `metagraph-sdk-core`.

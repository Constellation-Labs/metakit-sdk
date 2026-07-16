// Package jlvm is a reserved placeholder for the future Go port of the JLVM
// (JSON Logic Virtual Machine) extension tier.
//
// It mirrors the extension tier already present in the other language SDKs
// (e.g. the TypeScript `@constellation-network/metagraph-sdk-jlvm` package): the
// JLVM evaluator, the consensus gas schedule, and the zk / crypto opcodes
// (Poseidon, sigma proofs, curve arithmetic). None of that has been ported to
// Go yet, so this package intentionally contains no runnable source — only this
// declaration — to hold the import path and tier boundary in place.
//
// The JLVM extension is deliberately independent of the signing kernel (core)
// and the currency/network layer (std); when ported it must not depend on
// either.
package jlvm

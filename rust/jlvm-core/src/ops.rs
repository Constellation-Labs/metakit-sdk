//! The set of known operator tags. Mirrors `JsonLogicOp.knownOperatorTags`.

/// All operator tags recognized by the decoder, exactly as in `JsonLogicOp.scala`.
pub const KNOWN_OPERATORS: &[&str] = &[
    // Control flow
    "noop",
    "if",
    "default",
    "let",
    // Logical
    "!",
    "!!",
    "or",
    "and",
    // Comparison
    "==",
    "===",
    "!=",
    "!==",
    "<",
    "<=",
    ">",
    ">=",
    // Arithmetic
    "+",
    "-",
    "*",
    "/",
    "%",
    "max",
    "min",
    "abs",
    "round",
    "floor",
    "ceil",
    "pow",
    // Array
    "map",
    "filter",
    "reduce",
    "merge",
    "all",
    "some",
    "none",
    "find",
    "count",
    "in",
    "intersect",
    "unique",
    "slice",
    "reverse",
    "flatten",
    // String
    "cat",
    "substr",
    "lower",
    "upper",
    "join",
    "split",
    "trim",
    "startsWith",
    "endsWith",
    // Object/map
    "values",
    "keys",
    "get",
    "has",
    "entries",
    // Immutable map update -- mirrors JsonLogicOp SetOp / UnsetOp. `set` returns a
    // copy of the map with `key`->`value` (last-wins, position-preserving on an
    // existing key); `unset` returns a copy without `key` (absent key is a no-op).
    "set",
    "unset",
    // Utility
    "length",
    "exists",
    "missing",
    "missing_some",
    "typeof",
    // Hex conversion -- mirrors JsonLogicOp HexToIntOp. Parses a 0x-prefixed,
    // lowercase, big-endian hex string into an unsigned arbitrary-precision int.
    "hex_to_int",
    // ZK / crypto (Tier 1) -- mirrors JsonLogicOp PoseidonOp / PmtVerifyOp / SchnorrVerifyOp
    "poseidon",
    "pmt_verify",
    "schnorr_verify",
    // Auth-DB ZK verifiers (Tier 2a) -- mirrors JsonLogicOp SmtVerifyOp / MptVerifyOp / MptPrefixVerifyOp
    "smt_verify",
    "mpt_verify",
    "mpt_prefix_verify",
    // BN254 curve ops + ECVRF (Tier 2b) -- mirrors JsonLogicOp Bn254AddOp / Bn254MulOp / Bn254PairingOp / EcVrfVerifyOp
    "bn254_add",
    "bn254_mul",
    "bn254_pairing",
    "ecvrf_verify",
    // SP1 Groth16-BN254 verifier (Tier 3a) -- mirrors JsonLogicOp Groth16VerifyOp
    "groth16_verify",
    // BLS12-381 signatures (Tier 3b) -- mirrors JsonLogicOp BlsVerifyOp / BlsAggregateVerifyOp
    "bls_verify",
    "bls_aggregate_verify",
    // Sigma-protocol leaves + CDS tree verifier -- mirrors JsonLogicOp
    // ProveDlogVerifyOp / ProveDhTupleVerifyOp / SigmaVerifyOp.
    "prove_dlog_verify",
    "prove_dhtuple_verify",
    "sigma_verify",
];

pub fn is_known_operator(tag: &str) -> bool {
    KNOWN_OPERATORS.contains(&tag)
}

/// Whether the argument at `arg_index` of operator `op` is a lazily-wrapped callback
/// (a FunctionValue) rather than an eagerly-evaluated value. Mirrors `isCallbackArg`.
pub fn is_callback_arg(op: &str, arg_index: usize) -> bool {
    matches!(
        op,
        "map" | "filter" | "all" | "some" | "none" | "find" | "count" | "reduce"
    ) && arg_index == 1
}

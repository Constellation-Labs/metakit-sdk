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
    // Utility
    "length",
    "exists",
    "missing",
    "missing_some",
    "typeof",
    // ZK / crypto (Tier 1) -- mirrors JsonLogicOp PoseidonOp / PmtVerifyOp / SchnorrVerifyOp
    "poseidon",
    "pmt_verify",
    "schnorr_verify",
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

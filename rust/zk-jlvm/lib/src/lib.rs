use alloy_sol_types::sol;

sol! {
    /// Public values committed by the JLVM zkVM program.
    ///
    /// The proof attests: "evaluating the JSON Logic program with `keccak256(expr) == exprHash`
    /// on data with `keccak256(data) == dataHash` produces a canonical (RFC 8785) output with
    /// `keccak256(output) == outputHash`" — with `ok == false` (and `outputHash == 0`) if the
    /// program errored. These four fields are the on-chain-verifiable statement.
    struct JlvmPublicValues {
        bytes32 exprHash;
        bytes32 dataHash;
        bytes32 outputHash;
        bool ok;
    }
}

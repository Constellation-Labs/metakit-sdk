//! Gas schedule for the Tier-1 ZK / crypto opcodes.
//!
//! Mirrors the per-opcode `GasCost` constants in the Scala
//! `io.constellationnetwork.metagraph_sdk.json_logic.gas.GasMetering`
//! (`GasSchedule`). The base Rust JLVM evaluator is value-only (no metering
//! loop), so this module provides the *cost function* in lock-step with the
//! Scala schedule: it is the DoS bound a gas-aware host charges before
//! dispatching the opcode. Keeping the numbers here (and tested) guarantees the
//! Rust and Scala gas accounting stay in sync as the metered evaluator lands.
//!
//! Costs (Scala `GasSchedule` defaults):
//!   - `poseidon`:       150 base + 150 per input
//!   - `pmt_verify`:     200 base + 300 per sibling
//!   - `schnorr_verify`: 45_000 (flat)

/// Flat base cost of `poseidon`, before per-input widening.
pub const POSEIDON_BASE: u64 = 150;
/// Per-input cost of `poseidon` (each input widens the permutation).
pub const POSEIDON_PER_INPUT: u64 = 150;
/// Flat base cost of `pmt_verify`, before per-sibling path folding.
pub const PMT_VERIFY_BASE: u64 = 200;
/// Per-sibling cost of `pmt_verify` (one Poseidon compress per path level).
pub const PMT_PER_SIBLING: u64 = 300;
/// Flat cost of `schnorr_verify` (two BN254 scalar muls + point add + SHA-256).
pub const SCHNORR_VERIFY: u64 = 45_000;

/// Gas for a `poseidon` call over `num_inputs` field elements.
pub fn poseidon(num_inputs: usize) -> u64 {
    POSEIDON_BASE + POSEIDON_PER_INPUT * num_inputs as u64
}

/// Gas for a `pmt_verify` call over a proof with `num_siblings` siblings.
pub fn pmt_verify(num_siblings: usize) -> u64 {
    PMT_VERIFY_BASE + PMT_PER_SIBLING * num_siblings as u64
}

/// Gas for a `schnorr_verify` call (flat).
pub fn schnorr_verify() -> u64 {
    SCHNORR_VERIFY
}

/// The flat / base gas cost charged for an opcode tag before any per-element
/// component. Returns `None` for tags with no Tier-1 ZK cost entry.
pub fn base_cost(tag: &str) -> Option<u64> {
    match tag {
        "poseidon" => Some(POSEIDON_BASE),
        "pmt_verify" => Some(PMT_VERIFY_BASE),
        "schnorr_verify" => Some(SCHNORR_VERIFY),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matches_scala_schedule() {
        assert_eq!(poseidon(2), 150 + 150 * 2);
        assert_eq!(pmt_verify(8), 200 + 300 * 8);
        assert_eq!(schnorr_verify(), 45_000);
        assert_eq!(base_cost("poseidon"), Some(150));
        assert_eq!(base_cost("pmt_verify"), Some(200));
        assert_eq!(base_cost("schnorr_verify"), Some(45_000));
        assert_eq!(base_cost("+"), None);
    }
}

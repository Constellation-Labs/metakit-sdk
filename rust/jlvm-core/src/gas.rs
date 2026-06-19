//! Gas schedule for the JLVM, in lock-step with the Scala reference
//! (`io.constellationnetwork.metagraph_sdk.json_logic.gas.GasMetering`,
//! `GasConfig.Default`).
//!
//! [`GasConfig`] carries the FULL default schedule: every per-opcode base cost,
//! the depth-penalty multiplier, the variable-access cost, and the per-element /
//! size multipliers used by the input- and output-scaled charge components. The
//! metered evaluator lives in [`crate::gas_eval`]; the charging contract it
//! implements is normative per metakit PR #37:
//!
//!   - each op consumes EXACTLY ONCE:
//!     `base(op) + depth_penalty(depth) + input_scaled(op, args)` atomically
//!     BEFORE the primitive runs (so out-of-gas fires before any input-scaled
//!     work), plus an output-scaled residual AFTER it for
//!     split/merge/flatten/slice/substr only;
//!   - var lookups consume `var_access + #path_segments` once at lookup time;
//!   - the lazily-evaluated `if` / `let` charge their flat base cost
//!     (`if_else`) once per node at the dispatch site, with NO depth penalty
//!     (depth is undefined at the lazy dispatch site); untaken branches cost
//!     nothing;
//!   - reported gas-used is the gas-counter delta.
//!
//! All cost arithmetic is u64 saturating.

/// The full default gas schedule. Field-for-field mirror of the Scala
/// `GasConfig` defaults — when one side changes, the shared gas vectors
/// (`shared/gas_test_vectors.json`) catch the drift.
#[derive(Debug, Clone)]
pub struct GasConfig {
    pub if_else: u64,
    pub default: u64,
    pub not: u64,
    pub double_not: u64,
    pub or: u64,
    pub and: u64,
    pub eq: u64,
    pub eq_strict: u64,
    pub neq: u64,
    pub neq_strict: u64,
    pub lt: u64,
    pub leq: u64,
    pub gt: u64,
    pub geq: u64,
    pub add: u64,
    pub minus: u64,
    pub times: u64,
    pub div: u64,
    pub modulo: u64,
    pub max: u64,
    pub min: u64,
    pub abs: u64,
    pub round: u64,
    pub floor: u64,
    pub ceil: u64,
    pub pow: u64,
    pub map: u64,
    pub filter: u64,
    pub reduce: u64,
    pub merge: u64,
    pub all: u64,
    pub some: u64,
    pub none: u64,
    pub find: u64,
    pub count: u64,
    pub in_op: u64,
    pub intersect: u64,
    pub unique: u64,
    pub slice: u64,
    pub reverse: u64,
    pub flatten: u64,
    pub cat: u64,
    pub substr: u64,
    pub lower: u64,
    pub upper: u64,
    pub join: u64,
    pub split: u64,
    pub trim: u64,
    pub starts_with: u64,
    pub ends_with: u64,
    pub map_values: u64,
    pub map_keys: u64,
    pub get: u64,
    pub has: u64,
    pub entries: u64,
    pub length: u64,
    pub exists: u64,
    pub missing: u64,
    pub missing_some: u64,
    pub type_of: u64,
    /// `hex_to_int`: pinned EQUAL to `modulo` (a small fixed-cost decode + fold).
    pub hex_to_int: u64,
    pub poseidon: u64,
    pub poseidon_per_input: u64,
    pub pmt_verify: u64,
    pub pmt_per_sibling: u64,
    pub groth16_verify: u64,
    pub ecvrf_verify: u64,
    pub bn254_add: u64,
    pub bn254_mul: u64,
    pub bn254_pairing: u64,
    pub bn254_pairing_per_pair: u64,
    pub bls_verify: u64,
    pub bls_aggregate_verify: u64,
    pub bls_aggregate_per_key: u64,
    pub schnorr_verify: u64,
    pub smt_verify: u64,
    pub smt_per_sibling: u64,
    pub mpt_verify: u64,
    pub mpt_per_node: u64,
    pub mpt_prefix_verify: u64,
    pub mpt_prefix_per_entry: u64,
    pub prove_dlog_verify: u64,
    pub prove_dhtuple_verify: u64,
    pub sigma_verify: u64,
    pub sigma_verify_per_dlog_leaf: u64,
    pub sigma_verify_per_dhtuple_leaf: u64,
    pub sigma_verify_per_node: u64,
    pub const_cost: u64,
    pub var_access: u64,
    pub depth_penalty_multiplier: u64,
    pub collection_size_multiplier: u64,
}

impl Default for GasConfig {
    fn default() -> Self {
        GasConfig {
            if_else: 10,
            default: 5,
            not: 1,
            double_not: 1,
            or: 2,
            and: 2,
            eq: 3,
            eq_strict: 2,
            neq: 3,
            neq_strict: 2,
            lt: 3,
            leq: 3,
            gt: 3,
            geq: 3,
            add: 5,
            minus: 5,
            times: 8,
            div: 10,
            modulo: 10,
            max: 5,
            min: 5,
            abs: 2,
            round: 3,
            floor: 3,
            ceil: 3,
            pow: 20,
            map: 10,
            filter: 10,
            reduce: 15,
            merge: 5,
            all: 10,
            some: 10,
            none: 10,
            find: 10,
            count: 5,
            in_op: 8,
            intersect: 15,
            unique: 20,
            slice: 5,
            reverse: 5,
            flatten: 10,
            cat: 5,
            substr: 8,
            lower: 3,
            upper: 3,
            join: 10,
            split: 15,
            trim: 5,
            starts_with: 5,
            ends_with: 5,
            map_values: 5,
            map_keys: 5,
            get: 3,
            has: 3,
            entries: 10,
            length: 1,
            exists: 5,
            missing: 10,
            missing_some: 15,
            type_of: 1,
            hex_to_int: 10, // == modulo
            poseidon: 150,
            poseidon_per_input: 150,
            pmt_verify: 200,
            pmt_per_sibling: 300,
            groth16_verify: 250_000,
            ecvrf_verify: 50_000,
            bn254_add: 500,
            bn254_mul: 40_000,
            bn254_pairing: 45_000,
            bn254_pairing_per_pair: 35_000,
            bls_verify: 120_000,
            bls_aggregate_verify: 120_000,
            bls_aggregate_per_key: 15_000,
            schnorr_verify: 45_000,
            smt_verify: 500,
            smt_per_sibling: 400,
            mpt_verify: 500,
            mpt_per_node: 400,
            mpt_prefix_verify: 1_000,
            mpt_prefix_per_entry: 800,
            // Sigma protocols (Ergo/EIP-11 family). The two fixed-arity leaves are
            // flat (no input-scaled term): prove_dlog_verify is priced identically
            // to schnorr_verify (thin alias), prove_dhtuple_verify ~2x (4 muls + 2
            // adds). sigma_verify is the recursive CDS tree verifier: its cost is
            // pre-charged from the proposition-tree shape (per-leaf + per-node, see
            // `input_scaled_cost`).
            prove_dlog_verify: 45_000,
            prove_dhtuple_verify: 85_000,
            sigma_verify: 45_000,
            sigma_verify_per_dlog_leaf: 45_000,
            sigma_verify_per_dhtuple_leaf: 85_000,
            sigma_verify_per_node: 2_000,
            const_cost: 0,
            var_access: 2,
            depth_penalty_multiplier: 5,
            collection_size_multiplier: 1,
        }
    }
}

impl GasConfig {
    /// `depth * depthPenaltyMultiplier`, saturating. Mirrors `GasConfig.depthPenalty`.
    pub fn depth_penalty(&self, depth: u64) -> u64 {
        depth.saturating_mul(self.depth_penalty_multiplier)
    }

    /// `size * collectionSizeMultiplier`, saturating. Mirrors `GasConfig.sizeCost`.
    pub fn size_cost(&self, size: u64) -> u64 {
        size.saturating_mul(self.collection_size_multiplier)
    }

    /// The flat base cost charged for an operator tag, before the depth penalty
    /// and any input-scaled component. Mirrors `GasAwareSemantics.getOpCost`
    /// (NOTE the Scala quirks, reproduced deliberately: `missing` charges the
    /// `exists` cost, and `let` would charge the `if` cost — although the
    /// tail-recursive runtime never routes `if`/`let` through `applyOp`, so
    /// neither base cost is ever consumed in practice).
    ///
    /// Returns `None` for unknown operator tags.
    pub fn op_base_cost(&self, op: &str) -> Option<u64> {
        let cost = match op {
            "missing" => self.exists, // Scala: MissingNoneOp -> config.exists
            "exists" => self.exists,
            "missing_some" => self.missing_some,
            "if" => self.if_else,
            "let" => self.if_else, // Scala: LetOp -> config.ifElse
            "==" => self.eq,
            "===" => self.eq_strict,
            "!=" => self.neq,
            "!==" => self.neq_strict,
            "!" => self.not,
            "!!" => self.double_not,
            "or" => self.or,
            "and" => self.and,
            "<" => self.lt,
            "<=" => self.leq,
            ">" => self.gt,
            ">=" => self.geq,
            "%" => self.modulo,
            "max" => self.max,
            "min" => self.min,
            "+" => self.add,
            "*" => self.times,
            "-" => self.minus,
            "/" => self.div,
            "merge" => self.merge,
            "in" => self.in_op,
            "cat" => self.cat,
            "substr" => self.substr,
            "map" => self.map,
            "filter" => self.filter,
            "reduce" => self.reduce,
            "all" => self.all,
            "none" => self.none,
            "some" => self.some,
            "values" => self.map_values,
            "keys" => self.map_keys,
            "get" => self.get,
            "intersect" => self.intersect,
            "count" => self.count,
            "length" => self.length,
            "find" => self.find,
            "lower" => self.lower,
            "upper" => self.upper,
            "join" => self.join,
            "split" => self.split,
            "default" => self.default,
            "unique" => self.unique,
            "slice" => self.slice,
            "reverse" => self.reverse,
            "flatten" => self.flatten,
            "trim" => self.trim,
            "startsWith" => self.starts_with,
            "endsWith" => self.ends_with,
            "abs" => self.abs,
            "round" => self.round,
            "floor" => self.floor,
            "ceil" => self.ceil,
            "pow" => self.pow,
            "has" => self.has,
            "entries" => self.entries,
            "typeof" => self.type_of,
            "hex_to_int" => self.hex_to_int,
            "poseidon" => self.poseidon,
            "pmt_verify" => self.pmt_verify,
            "groth16_verify" => self.groth16_verify,
            "ecvrf_verify" => self.ecvrf_verify,
            "bn254_add" => self.bn254_add,
            "bn254_mul" => self.bn254_mul,
            "bn254_pairing" => self.bn254_pairing,
            "bls_verify" => self.bls_verify,
            "bls_aggregate_verify" => self.bls_aggregate_verify,
            "schnorr_verify" => self.schnorr_verify,
            "smt_verify" => self.smt_verify,
            "mpt_verify" => self.mpt_verify,
            "mpt_prefix_verify" => self.mpt_prefix_verify,
            "prove_dlog_verify" => self.prove_dlog_verify,
            "prove_dhtuple_verify" => self.prove_dhtuple_verify,
            "sigma_verify" => self.sigma_verify,
            _ => return None,
        };
        Some(cost)
    }
}

// --- legacy Tier-1 helpers ----------------------------------------------------
//
// Kept for back-compat with earlier callers; the constants are asserted equal to
// the full schedule below so they cannot drift.

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

    #[test]
    fn legacy_constants_agree_with_full_schedule() {
        let c = GasConfig::default();
        assert_eq!(POSEIDON_BASE, c.poseidon);
        assert_eq!(POSEIDON_PER_INPUT, c.poseidon_per_input);
        assert_eq!(PMT_VERIFY_BASE, c.pmt_verify);
        assert_eq!(PMT_PER_SIBLING, c.pmt_per_sibling);
        assert_eq!(SCHNORR_VERIFY, c.schnorr_verify);
    }

    #[test]
    fn full_schedule_spot_checks() {
        let c = GasConfig::default();
        // One representative per family against the Scala GasConfig defaults.
        assert_eq!(c.op_base_cost("+"), Some(5));
        assert_eq!(c.op_base_cost("*"), Some(8));
        assert_eq!(c.op_base_cost("pow"), Some(20));
        assert_eq!(c.op_base_cost("map"), Some(10));
        assert_eq!(c.op_base_cost("reduce"), Some(15));
        assert_eq!(c.op_base_cost("unique"), Some(20));
        assert_eq!(c.op_base_cost("split"), Some(15));
        assert_eq!(c.op_base_cost("typeof"), Some(1));
        // hex_to_int is pinned EQUAL to the modulo (`%`) base cost, and must
        // match the TypeScript gas module byte-for-byte.
        assert_eq!(c.op_base_cost("hex_to_int"), c.op_base_cost("%"));
        assert_eq!(c.op_base_cost("hex_to_int"), Some(10));
        // Scala quirk: `missing` charges the `exists` cost (5), not `missing` (10).
        assert_eq!(c.op_base_cost("missing"), Some(5));
        assert_eq!(c.op_base_cost("missing_some"), Some(15));
        assert_eq!(c.op_base_cost("groth16_verify"), Some(250_000));
        assert_eq!(c.op_base_cost("ecvrf_verify"), Some(50_000));
        assert_eq!(c.op_base_cost("bn254_pairing"), Some(45_000));
        assert_eq!(c.op_base_cost("bls_aggregate_verify"), Some(120_000));
        assert_eq!(c.op_base_cost("smt_verify"), Some(500));
        assert_eq!(c.op_base_cost("mpt_prefix_verify"), Some(1_000));
        // Sigma opcodes: leaves are flat; sigma_verify base is pre-charged with
        // per-leaf/per-node terms applied from the proposition shape (see gas_eval).
        assert_eq!(c.op_base_cost("prove_dlog_verify"), Some(45_000));
        assert_eq!(c.op_base_cost("prove_dhtuple_verify"), Some(85_000));
        assert_eq!(c.op_base_cost("sigma_verify"), Some(45_000));
        assert_eq!(c.sigma_verify_per_dlog_leaf, 45_000);
        assert_eq!(c.sigma_verify_per_dhtuple_leaf, 85_000);
        assert_eq!(c.sigma_verify_per_node, 2_000);
        assert_eq!(c.op_base_cost("not_an_op"), None);
        assert_eq!(c.depth_penalty(3), 15);
        assert_eq!(c.size_cost(7), 7);
        assert_eq!(c.var_access, 2);
    }
}

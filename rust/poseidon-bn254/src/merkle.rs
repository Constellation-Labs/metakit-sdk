//! A fixed-depth, sparse, incremental Poseidon Merkle tree over BN254 Fr,
//! BYTE-COMPATIBLE with metakit's Scala `PoseidonMerkleTree`.
//!
//! Conventions (copied EXACTLY from the Scala side):
//!
//! - depth default 32; leaves are Fr in `[0, R)`. The canonical empty leaf is `0`.
//! - Empty-subtree "zero" hashes: `zero(0) = 0`, `zero(i) = compress(zero(i-1), zero(i-1))`.
//!   The empty-tree root is `zero(depth)`.
//! - Position bits are LSB-first; bit `i` selects the child at LEVEL `i`, level 0 adjacent
//!   to the leaf. bit==0 => path node is the LEFT child => `compress(current, sibling)`;
//!   bit==1 => path node is the RIGHT child => `compress(sibling, current)`. Hashing always
//!   preserves left/right child order: `parent = compress(left, right)`.
//! - Proof siblings are stored ROOT-FIRST (top-down): `siblings[0]` is the other child of the
//!   root, `siblings[depth-1]` is adjacent to the leaf. Verification folds bottom-up (reverse).
//!   A proof always carries exactly `depth` siblings.
//! - The root is a pure function of the live `position -> leaf` map (order-independent).
//! - Absence == inclusion of the ZERO leaf: an absence proof is the same authentication path,
//!   folded with leaf = `0`.

use crate::{compress, is_canonical, zero};
use num_bigint::BigUint;
use num_traits::{One, Zero};
use std::collections::HashMap;

/// The default fixed depth (capacity `2^32` positions).
pub const DEFAULT_DEPTH: usize = 32;

/// An authentication path against a tree root. `position` and every `sibling` are
/// canonical Fr elements; `siblings` is root-first and always has length `depth`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PoseidonMerkleProof {
    pub position: BigUint,
    pub siblings: Vec<BigUint>,
}

impl PoseidonMerkleProof {
    /// The fixed depth of the tree this proof was produced against (= number of siblings).
    pub fn depth(&self) -> usize {
        self.siblings.len()
    }
}

/// A fixed-depth sparse Poseidon Merkle tree.
#[derive(Clone, Debug)]
pub struct PoseidonMerkleTree {
    depth: usize,
    zero_hashes: Vec<BigUint>,
    /// Materialised non-empty subtree digests keyed by `(level, index-at-level)`.
    /// A leaf is `(0, position)`; the root is `(depth, 0)`. Zero-hash entries are pruned.
    nodes: HashMap<(usize, BigUint), BigUint>,
    /// The live, non-zero leaves keyed by position (the logical contents).
    leaves: HashMap<BigUint, BigUint>,
}

/// Precompute the empty-subtree ("zero") hashes for a tree of the given depth,
/// indexable as `0..=depth`. `zero_hashes[depth]` is the empty-tree root.
pub fn zero_hashes(depth: usize) -> Vec<BigUint> {
    assert!(depth >= 1, "depth must be >= 1; got {depth}");
    let mut v = Vec::with_capacity(depth + 1);
    let mut prev = zero();
    v.push(prev.clone());
    for _ in 1..=depth {
        prev = compress(&prev, &prev);
        v.push(prev.clone());
    }
    v
}

impl PoseidonMerkleTree {
    /// An empty tree of [`DEFAULT_DEPTH`].
    pub fn empty_default() -> Self {
        Self::empty(DEFAULT_DEPTH)
    }

    /// An empty tree of the given fixed `depth` (capacity `2^depth`).
    pub fn empty(depth: usize) -> Self {
        PoseidonMerkleTree {
            depth,
            zero_hashes: zero_hashes(depth),
            nodes: HashMap::new(),
            leaves: HashMap::new(),
        }
    }

    /// Build a tree of the given `depth` directly from `position -> leaf` entries
    /// (order-independent).
    pub fn from_leaves(
        depth: usize,
        entries: impl IntoIterator<Item = (BigUint, BigUint)>,
    ) -> Self {
        let mut t = Self::empty(depth);
        for (p, l) in entries {
            t.insert(&p, &l);
        }
        t
    }

    pub fn depth(&self) -> usize {
        self.depth
    }

    /// The number of positions this tree can hold (`2^depth`).
    pub fn capacity(&self) -> BigUint {
        BigUint::one() << self.depth
    }

    /// The root commitment (the empty-tree root `zero(depth)` when no leaves are set).
    pub fn root(&self) -> BigUint {
        self.nodes
            .get(&(self.depth, BigUint::zero()))
            .cloned()
            .unwrap_or_else(|| self.zero_hashes[self.depth].clone())
    }

    /// The leaf currently stored at `position` (zero if never set).
    pub fn leaf_at(&self, position: &BigUint) -> BigUint {
        self.require_position(position);
        self.leaves.get(position).cloned().unwrap_or_else(zero)
    }

    /// True iff `position` currently holds a non-zero leaf.
    pub fn is_set(&self, position: &BigUint) -> bool {
        self.leaves.contains_key(position)
    }

    /// Store `leaf` at `position`, recomputing only the digests on its root-to-leaf path.
    /// Inserting the zero leaf clears the position back to empty. Mutates in place.
    pub fn insert(&mut self, position: &BigUint, leaf: &BigUint) {
        self.require_position(position);
        assert!(
            is_canonical(leaf),
            "leaf at position {position} is not a canonical BN254 field element (must be in [0, R)): {leaf}"
        );

        if leaf.is_zero() {
            self.leaves.remove(position);
        } else {
            self.leaves.insert(position.clone(), leaf.clone());
        }

        // Recompute the path bottom-up, updating (or pruning) one node per level.
        let mut idx = position.clone();
        let mut digest = leaf.clone();
        for level in 0..=self.depth {
            if digest == self.zero_hashes[level] {
                self.nodes.remove(&(level, idx.clone()));
            } else {
                self.nodes.insert((level, idx.clone()), digest.clone());
            }
            if level == self.depth {
                break;
            }
            // bit `level` of `position` decides whether `idx` is the left (0) or right (1) child.
            let bit = position.bit(level as u64);
            let sibling_idx = if bit { &idx - 1u32 } else { &idx + 1u32 };
            let sibling = self
                .nodes
                .get(&(level, sibling_idx))
                .cloned()
                .unwrap_or_else(|| self.zero_hashes[level].clone());
            digest = if bit {
                compress(&sibling, &digest) // path node is the RIGHT child
            } else {
                compress(&digest, &sibling) // path node is the LEFT child
            };
            idx >>= 1;
        }
    }

    /// A builder-style insert returning `self` (handy for chaining in tests).
    pub fn with_leaf(mut self, position: &BigUint, leaf: &BigUint) -> Self {
        self.insert(position, leaf);
        self
    }

    /// The authentication path (root-first sibling digests) for `position`. Shape-identical
    /// whether the position is set (inclusion) or empty (absence). Returns exactly `depth`
    /// siblings.
    pub fn proof(&self, position: &BigUint) -> PoseidonMerkleProof {
        self.require_position(position);
        let mut bottom_up: Vec<BigUint> = Vec::with_capacity(self.depth);
        let mut idx = position.clone();
        for level in 0..self.depth {
            let bit = position.bit(level as u64);
            let sibling_idx = if bit { &idx - 1u32 } else { &idx + 1u32 };
            let sibling = self
                .nodes
                .get(&(level, sibling_idx))
                .cloned()
                .unwrap_or_else(|| self.zero_hashes[level].clone());
            bottom_up.push(sibling);
            idx >>= 1;
        }
        // Collected bottom-first; reverse to root-first (top-down) ordering.
        bottom_up.reverse();
        PoseidonMerkleProof {
            position: position.clone(),
            siblings: bottom_up,
        }
    }

    /// An INCLUSION proof for `leaf_at(position)`. Identical in shape to [`proof`](Self::proof).
    pub fn inclusion_proof(&self, position: &BigUint) -> PoseidonMerkleProof {
        self.proof(position)
    }

    /// An ABSENCE proof for `position` (must currently be empty). The verifier folds the
    /// ZERO leaf and checks it equals the root.
    pub fn absence_proof(&self, position: &BigUint) -> PoseidonMerkleProof {
        self.require_position(position);
        assert!(
            !self.is_set(position),
            "cannot produce an absence proof for position {position}: it holds a non-zero leaf"
        );
        self.proof(position)
    }

    fn require_position(&self, position: &BigUint) {
        assert!(
            *position < self.capacity(),
            "position out of range: must be in [0, 2^{}); got {position}",
            self.depth
        );
    }
}

/// The fold at the heart of BOTH inclusion and absence verification: fold `leaf` up the
/// authentication path and return the recomputed root. `proof.siblings` is root-first, so
/// it is consumed in reverse (bottom-up). Inputs are validated as canonical Fr.
///
/// At level `i` (from the bottom), bit `i` of `proof.position` selects left/right:
///   - bit==0 => path node is the LEFT child:  `parent = compress(current, sibling)`,
///   - bit==1 => path node is the RIGHT child: `parent = compress(sibling, current)`.
pub fn compute_root(leaf: &BigUint, proof: &PoseidonMerkleProof) -> BigUint {
    assert!(
        is_canonical(leaf),
        "leaf is not a canonical BN254 field element: {leaf}"
    );
    for (i, s) in proof.siblings.iter().enumerate() {
        assert!(
            is_canonical(s),
            "sibling[{i}] is not a canonical BN254 field element: {s}"
        );
    }
    let depth = proof.depth();
    assert!(
        proof.position < (BigUint::one() << depth),
        "proof position out of range for depth {depth}: {}",
        proof.position
    );

    // siblings are root-first; reverse to fold from the leaf upward (bottom level = index 0).
    let mut current = leaf.clone();
    for (level, sibling) in proof.siblings.iter().rev().enumerate() {
        current = if proof.position.bit(level as u64) {
            compress(sibling, &current) // path node is RIGHT child
        } else {
            compress(&current, sibling) // path node is LEFT child
        };
    }
    current
}

/// Verify an INCLUSION proof: `leaf` is committed at `proof.position` under `root`.
pub fn verify_inclusion(leaf: &BigUint, proof: &PoseidonMerkleProof, root: &BigUint) -> bool {
    &compute_root(leaf, proof) == root
}

/// Verify an ABSENCE proof: `proof.position` still holds the ZERO leaf under `root`.
/// Exactly [`verify_inclusion`] with the claimed leaf fixed to zero.
pub fn verify_absence(proof: &PoseidonMerkleProof, root: &BigUint) -> bool {
    verify_inclusion(&zero(), proof, root)
}

//! Correctness suite for the fixed-depth Poseidon Merkle tree, mirroring metakit's
//! Scala `PoseidonMerkleTreeSuite`, plus the two REQUIRED emitted roots for the
//! cross-repo diff:
//!   (a) the empty depth-8 root, and
//!   (b) the root after inserting leaf = poseidon([7]) at position 3 in a depth-8 tree.

use num_bigint::BigUint;
use poseidon_bn254::merkle::{
    compute_root, verify_absence, verify_inclusion, zero_hashes, PoseidonMerkleTree, DEFAULT_DEPTH,
};
use poseidon_bn254::{compress, hash, is_canonical, zero};

const DEPTH: usize = 8; // capacity 256; spans both bit values at every level.

fn pos(n: u64) -> BigUint {
    BigUint::from(n)
}
fn commitment(seed: u64) -> BigUint {
    hash(&[BigUint::from(seed), BigUint::from(seed + 1)])
}
fn to_hex(x: &BigUint) -> String {
    format!("0x{:064x}", x)
}

// ---- REQUIRED EMITTED ROOTS (for diffing against Scala) --------------------------------------

#[test]
fn emit_required_roots() {
    let empty = PoseidonMerkleTree::empty(DEPTH);
    let empty_root = empty.root();

    let leaf7 = hash(&[BigUint::from(7u8)]); // poseidon([7])
    let mut tree = PoseidonMerkleTree::empty(DEPTH);
    tree.insert(&pos(3), &leaf7);
    let root_after = tree.root();

    println!("--- REQUIRED Poseidon Merkle roots (hex) for cross-check vs Scala ---");
    println!(
        "(a) empty depth-8 root                          = {}",
        to_hex(&empty_root)
    );
    println!(
        "    leaf = poseidon([7])                        = {}",
        to_hex(&leaf7)
    );
    println!(
        "(b) depth-8 root after insert(pos=3, poseidon([7])) = {}",
        to_hex(&root_after)
    );

    // Internal consistency: inclusion verifies; tampered path fails; absence flips.
    let incl = tree.inclusion_proof(&pos(3));
    assert!(
        verify_inclusion(&leaf7, &incl, &root_after),
        "inclusion must verify"
    );
    assert_eq!(incl.siblings.len(), DEPTH);

    // absence at pos 3 fails (now occupied); absence at an unset pos verifies.
    assert!(
        !verify_absence(&incl, &root_after),
        "absence at occupied pos must fail"
    );
    let abs = tree.absence_proof(&pos(100));
    assert!(
        verify_absence(&abs, &root_after),
        "absence at unset pos must verify"
    );
}

// ---- zero hashes / empty tree ----------------------------------------------------------------

#[test]
fn zero_hashes_follow_convention() {
    let z = zero_hashes(DEPTH);
    assert_eq!(z[0], zero());
    assert_eq!(z.len(), DEPTH + 1);
    for i in 1..=DEPTH {
        assert_eq!(z[i], compress(&z[i - 1], &z[i - 1]));
    }
    for h in &z {
        assert!(is_canonical(h));
    }
}

#[test]
fn empty_tree_root_equals_zero_depth() {
    let t = PoseidonMerkleTree::empty(DEPTH);
    assert_eq!(t.root(), zero_hashes(DEPTH)[DEPTH]);
}

#[test]
fn default_depth_is_32() {
    let t = PoseidonMerkleTree::empty_default();
    assert_eq!(t.depth(), DEFAULT_DEPTH);
    assert_eq!(t.root(), zero_hashes(DEFAULT_DEPTH)[DEFAULT_DEPTH]);
}

// ---- inclusion -------------------------------------------------------------------------------

#[test]
fn single_inserted_leaf_inclusion_verifies() {
    let p = pos(173);
    let leaf = commitment(99);
    let mut t = PoseidonMerkleTree::empty(DEPTH);
    t.insert(&p, &leaf);
    let proof = t.inclusion_proof(&p);
    assert_eq!(proof.siblings.len(), DEPTH);
    assert!(verify_inclusion(&leaf, &proof, &t.root()));
    // free compute_root must agree
    assert_eq!(compute_root(&leaf, &proof), t.root());
}

#[test]
fn many_leaves_each_inclusion_verifies() {
    let mut t = PoseidonMerkleTree::empty(DEPTH);
    let entries: Vec<(BigUint, BigUint)> = (0u64..20)
        .map(|i| (pos(i * 11 % 256), commitment(i + 1)))
        .collect();
    for (p, l) in &entries {
        t.insert(p, l);
    }
    let root = t.root();
    // Use the final-state leaf (last write wins on a position) for verification.
    for p in entries
        .iter()
        .map(|(p, _)| p.clone())
        .collect::<std::collections::BTreeSet<_>>()
    {
        let leaf = t.leaf_at(&p);
        let proof = t.inclusion_proof(&p);
        assert!(
            verify_inclusion(&leaf, &proof, &root),
            "pos {p} inclusion failed"
        );
    }
}

#[test]
fn same_leaf_two_positions_distinct_proofs() {
    let leaf = commitment(7);
    let mut t = PoseidonMerkleTree::empty(DEPTH);
    t.insert(&pos(0), &leaf);
    t.insert(&pos(255), &leaf);
    let p0 = t.inclusion_proof(&pos(0));
    let p255 = t.inclusion_proof(&pos(255));
    assert_ne!(p0.siblings, p255.siblings);
    assert!(verify_inclusion(&leaf, &p0, &t.root()));
    assert!(verify_inclusion(&leaf, &p255, &t.root()));
}

// ---- tamper rejection ------------------------------------------------------------------------

#[test]
fn tampered_leaf_rejected() {
    let p = pos(42);
    let leaf = commitment(1);
    let mut t = PoseidonMerkleTree::empty(DEPTH);
    t.insert(&p, &leaf);
    let proof = t.inclusion_proof(&p);
    assert!(!verify_inclusion(&commitment(2), &proof, &t.root()));
}

#[test]
fn tampered_sibling_rejected() {
    let p = pos(123);
    let leaf = commitment(5);
    let mut t = PoseidonMerkleTree::empty(DEPTH);
    t.insert(&p, &leaf);
    for tamper_at in 0..DEPTH {
        let mut proof = t.inclusion_proof(&p);
        proof.siblings[tamper_at] = poseidon_bn254::reduce(&(&proof.siblings[tamper_at] + 1u32));
        assert!(
            !verify_inclusion(&leaf, &proof, &t.root()),
            "tamper at {tamper_at} not caught"
        );
    }
}

#[test]
fn wrong_position_path_rejected() {
    let mut t = PoseidonMerkleTree::empty(DEPTH);
    t.insert(&pos(10), &commitment(10));
    t.insert(&pos(11), &commitment(11));
    let proof_for_10 = t.inclusion_proof(&pos(10));
    assert!(!verify_inclusion(&commitment(11), &proof_for_10, &t.root()));
}

// ---- absence (nullifier non-membership) ------------------------------------------------------

#[test]
fn absence_verifies_for_unset_position() {
    let mut t = PoseidonMerkleTree::empty(DEPTH);
    t.insert(&pos(5), &commitment(5));
    let proof = t.absence_proof(&pos(200));
    assert_eq!(proof.siblings.len(), DEPTH);
    assert!(verify_absence(&proof, &t.root()));
}

#[test]
fn absence_before_insert_fails_after() {
    let p = pos(200);
    let mut before = PoseidonMerkleTree::empty(DEPTH);
    before.insert(&pos(5), &commitment(5));
    let absence = before.absence_proof(&p);
    assert!(verify_absence(&absence, &before.root()));

    let mut after = before.clone();
    after.insert(&p, &commitment(123)); // spend the slot
    assert!(!verify_absence(&absence, &after.root()));
}

#[test]
fn fresh_absence_fails_for_set_position() {
    let p = pos(77);
    let mut t = PoseidonMerkleTree::empty(DEPTH);
    t.insert(&p, &commitment(77));
    let path = t.inclusion_proof(&p);
    assert!(!verify_absence(&path, &t.root()));
    assert!(verify_inclusion(&t.leaf_at(&p), &path, &t.root()));
}

#[test]
#[should_panic]
fn absence_proof_refused_for_set_position() {
    let p = pos(77);
    let mut t = PoseidonMerkleTree::empty(DEPTH);
    t.insert(&p, &commitment(77));
    let _ = t.absence_proof(&p);
}

#[test]
fn clearing_position_restores_absence() {
    let p = pos(77);
    let mut t = PoseidonMerkleTree::empty(DEPTH);
    t.insert(&p, &commitment(77));
    t.insert(&p, &zero()); // clear back to empty
    assert!(!t.is_set(&p));
    assert_eq!(t.leaf_at(&p), zero());
    assert!(verify_absence(&t.absence_proof(&p), &t.root()));
    assert_eq!(t.root(), PoseidonMerkleTree::empty(DEPTH).root());
}

// ---- determinism / order independence --------------------------------------------------------

#[test]
fn root_independent_of_insertion_order() {
    let entries: Vec<(BigUint, BigUint)> = (0u64..16)
        .map(|i| (pos((i * 17 + 3) % 256), commitment(i + 1)))
        .collect();
    let mut forward = PoseidonMerkleTree::empty(DEPTH);
    for (p, l) in &entries {
        forward.insert(p, l);
    }
    let mut reversed = PoseidonMerkleTree::empty(DEPTH);
    for (p, l) in entries.iter().rev() {
        reversed.insert(p, l);
    }
    assert_eq!(forward.root(), reversed.root());
}

#[test]
fn reinsert_same_is_idempotent() {
    let p = pos(123);
    let leaf = commitment(123);
    let mut once = PoseidonMerkleTree::empty(DEPTH);
    once.insert(&p, &leaf);
    let mut twice = once.clone();
    twice.insert(&p, &leaf);
    assert_eq!(once.root(), twice.root());
}

#[test]
fn overwrite_changes_root_deterministically() {
    let p = pos(123);
    let mut a = PoseidonMerkleTree::empty(DEPTH);
    a.insert(&p, &commitment(1));
    let mut b = a.clone();
    b.insert(&p, &commitment(2));
    let mut direct = PoseidonMerkleTree::empty(DEPTH);
    direct.insert(&p, &commitment(2));
    assert_ne!(a.root(), b.root());
    assert_eq!(b.root(), direct.root());
    assert_eq!(b.leaf_at(&p), commitment(2));
}

// ---- validation ------------------------------------------------------------------------------

#[test]
fn root_is_canonical() {
    let mut t = PoseidonMerkleTree::empty(DEPTH);
    t.insert(&pos(1), &commitment(1));
    t.insert(&pos(200), &commitment(2));
    assert!(is_canonical(&t.root()));
}

#[test]
#[should_panic]
fn rejects_non_canonical_leaf() {
    let mut t = PoseidonMerkleTree::empty(DEPTH);
    t.insert(&pos(0), poseidon_bn254::modulus());
}

#[test]
#[should_panic]
fn rejects_out_of_range_position() {
    let mut t = PoseidonMerkleTree::empty(DEPTH);
    let cap = t.capacity();
    t.insert(&cap, &commitment(1));
}

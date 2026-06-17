//! Native-execution tests for the shielded-transfer constraint system. These run the
//! EXACT `verify_transfer` the zkVM guest runs, on a valid 2-in/2-out transfer and on
//! every invalid case (each must be rejected). They also round-trip the witness through
//! the JSON wire form and check public-values sol encode/decode.

use num_bigint::BigUint;
use poseidon_bn254::merkle::PoseidonMerkleTree;
use zk_shielded_lib::pub_values::ShieldedTransferPublicValues;
use zk_shielded_lib::wire::WireWitness;
use zk_shielded_lib::{
    nullifier, owner_from_nsk, verify_transfer, Note, OutputNote, SpendInput, TransferError,
    TransferWitness,
};

const DEPTH: usize = 8;

fn fr(n: u64) -> BigUint {
    BigUint::from(n)
}

/// Build a valid 2-in/2-out transfer: two input notes (owned via nsk_a/nsk_b) sitting in
/// a depth-8 commitment tree, two output notes, balanced with a fee.
struct Fixture {
    witness: TransferWitness,
    /// expected nullifiers / output cms for assertion convenience
    expected_nf: Vec<BigUint>,
    expected_cm: Vec<BigUint>,
}

fn valid_fixture() -> Fixture {
    let asset = fr(1); // single asset type

    // input owners
    let nsk_a = fr(111);
    let nsk_b = fr(222);
    let owner_a = owner_from_nsk(&nsk_a);
    let owner_b = owner_from_nsk(&nsk_b);

    // input notes: values 100 and 50
    let in_a = Note::new(100, owner_a.clone(), asset.clone(), fr(7001));
    let in_b = Note::new(50, owner_b.clone(), asset.clone(), fr(7002));

    // place commitments in the tree at positions 3 and 200
    let cm_a = in_a.commitment();
    let cm_b = in_b.commitment();
    let mut tree = PoseidonMerkleTree::empty(DEPTH);
    tree.insert(&fr(3), &cm_a);
    tree.insert(&fr(200), &cm_b);
    let anchor = tree.root();

    let proof_a = tree.inclusion_proof(&fr(3));
    let proof_b = tree.inclusion_proof(&fr(200));

    // outputs: values 120 and 25; fee 5; total in = 150, out+fee = 120+25+5 = 150.
    let nsk_c = fr(333);
    let nsk_d = fr(444);
    let out_c = Note::new(120, owner_from_nsk(&nsk_c), asset.clone(), fr(8001));
    let out_d = Note::new(25, owner_from_nsk(&nsk_d), asset.clone(), fr(8002));
    let fee = 5u64;

    let expected_nf = vec![nullifier(&in_a.rho, &nsk_a), nullifier(&in_b.rho, &nsk_b)];
    let expected_cm = vec![out_c.commitment(), out_d.commitment()];

    let witness = TransferWitness {
        anchor,
        inputs: vec![
            SpendInput { note: in_a, nsk: nsk_a, merkle_proof: proof_a },
            SpendInput { note: in_b, nsk: nsk_b, merkle_proof: proof_b },
        ],
        outputs: vec![OutputNote { note: out_c }, OutputNote { note: out_d }],
        fee,
        fee_asset: asset, // fee charged in the (single) transfer asset
    };

    Fixture { witness, expected_nf, expected_cm }
}

#[test]
fn valid_2in_2out_passes() {
    let f = valid_fixture();
    let public = verify_transfer(&f.witness).expect("valid transfer must pass");
    assert_eq!(public.anchor, f.witness.anchor);
    assert_eq!(public.nullifiers, f.expected_nf);
    assert_eq!(public.output_cms, f.expected_cm);
    assert_eq!(public.fee, 5);
}

#[test]
fn invalid_unbalanced_value_rejected() {
    let mut f = valid_fixture();
    // Inflate an output so sum(out)+fee > sum(in).
    f.witness.outputs[0].note.value += 1;
    match verify_transfer(&f.witness) {
        Err(TransferError::AssetNotConserved { .. }) => {}
        other => panic!("expected AssetNotConserved, got {other:?}"),
    }
}

#[test]
fn invalid_wrong_anchor_rejected() {
    let mut f = valid_fixture();
    // Corrupt the anchor: membership can no longer verify.
    f.witness.anchor += 1u32;
    match verify_transfer(&f.witness) {
        Err(TransferError::NotMember(_)) => {}
        other => panic!("expected NotMember (wrong anchor), got {other:?}"),
    }
}

#[test]
fn invalid_wrong_merkle_path_rejected() {
    let mut f = valid_fixture();
    // Tamper one sibling in input 0's proof.
    let s = &mut f.witness.inputs[0].merkle_proof.siblings[0];
    *s = poseidon_bn254::reduce(&(&*s + 1u32));
    match verify_transfer(&f.witness) {
        Err(TransferError::NotMember(0)) => {}
        other => panic!("expected NotMember(0) (tampered path), got {other:?}"),
    }
}

#[test]
fn invalid_wrong_position_rejected() {
    let mut f = valid_fixture();
    // Use a position that does not match the real leaf placement.
    f.witness.inputs[1].merkle_proof.position = fr(201);
    match verify_transfer(&f.witness) {
        Err(TransferError::NotMember(1)) => {}
        other => panic!("expected NotMember(1) (wrong position), got {other:?}"),
    }
}

#[test]
fn invalid_wrong_nsk_owner_mismatch_rejected() {
    let mut f = valid_fixture();
    // Spend input 0 with the wrong secret key: owner != Poseidon([nsk]).
    f.witness.inputs[0].nsk = fr(999);
    match verify_transfer(&f.witness) {
        Err(TransferError::OwnerMismatch(0)) => {}
        other => panic!("expected OwnerMismatch(0), got {other:?}"),
    }
}

#[test]
fn invalid_malformed_nullifier_is_caught_via_owner() {
    // A "malformed nullifier" can only arise from a wrong (rho, nsk). Since nf is DERIVED
    // in-guest (never supplied), the way to attempt a forged nullifier is to change nsk —
    // which then fails AUTHORIZATION. This documents that nf cannot be independently forged.
    let mut f = valid_fixture();
    let orig_nf = nullifier(&f.witness.inputs[0].note.rho, &f.witness.inputs[0].nsk);
    f.witness.inputs[0].nsk = fr(12345); // would change nf, but...
    let forged_nf = nullifier(&f.witness.inputs[0].note.rho, &f.witness.inputs[0].nsk);
    assert_ne!(orig_nf, forged_nf);
    // ...the transfer is rejected before any nullifier is accepted.
    assert!(matches!(verify_transfer(&f.witness), Err(TransferError::OwnerMismatch(0))));
}

#[test]
fn invalid_no_inputs_rejected() {
    let mut f = valid_fixture();
    f.witness.inputs.clear();
    assert_eq!(verify_transfer(&f.witness), Err(TransferError::NoInputs));
}

#[test]
fn invalid_no_outputs_rejected() {
    let mut f = valid_fixture();
    f.witness.outputs.clear();
    // sum_in (150) != 0 + fee, but NoOutputs is checked first.
    assert_eq!(verify_transfer(&f.witness), Err(TransferError::NoOutputs));
}

#[test]
fn invalid_non_canonical_field_rejected() {
    let mut f = valid_fixture();
    f.witness.inputs[0].note.asset = poseidon_bn254::modulus().clone(); // == R, not canonical
    assert!(matches!(verify_transfer(&f.witness), Err(TransferError::NonCanonical(_))));
}

#[test]
fn zero_fee_balanced_transfer_passes() {
    let asset = fr(1);
    let nsk = fr(5);
    let owner = owner_from_nsk(&nsk);
    let note = Note::new(77, owner.clone(), asset.clone(), fr(900));
    let cm = note.commitment();
    let mut tree = PoseidonMerkleTree::empty(DEPTH);
    tree.insert(&fr(9), &cm);
    let anchor = tree.root();
    let proof = tree.inclusion_proof(&fr(9));

    let out = Note::new(77, owner_from_nsk(&fr(6)), asset.clone(), fr(901));
    let witness = TransferWitness {
        anchor,
        inputs: vec![SpendInput { note, nsk, merkle_proof: proof }],
        outputs: vec![OutputNote { note: out }],
        fee: 0,
        fee_asset: asset,
    };
    assert!(verify_transfer(&witness).is_ok());
}

#[test]
fn invalid_duplicate_input_rejected() {
    // List the SAME input note twice: identical (rho, nsk) -> identical nullifier. Without the
    // intra-transfer uniqueness check this would double-count the note into its asset's input
    // sum (an intra-transfer double-spend the on-chain nullifier set can't catch on its own).
    let mut f = valid_fixture();
    f.witness.inputs[1] = f.witness.inputs[0].clone();
    match verify_transfer(&f.witness) {
        Err(TransferError::DuplicateNullifier(1)) => {}
        other => panic!("expected DuplicateNullifier(1), got {other:?}"),
    }
}

#[test]
fn invalid_cross_asset_mint_rejected() {
    // A transfer that BALANCES IN TOTAL but mints across assets: spend 100 of asset 1, create
    // 100 of asset 2, fee 0. The old total-only check accepted this; per-asset conservation
    // must reject it (this is the multi-asset MINT hole).
    let nsk = fr(5);
    let owner = owner_from_nsk(&nsk);
    let in_note = Note::new(100, owner, fr(1), fr(900));
    let mut tree = PoseidonMerkleTree::empty(DEPTH);
    tree.insert(&fr(9), &in_note.commitment());
    let anchor = tree.root();
    let proof = tree.inclusion_proof(&fr(9));

    let out = Note::new(100, owner_from_nsk(&fr(6)), fr(2), fr(901)); // DIFFERENT asset
    let witness = TransferWitness {
        anchor,
        inputs: vec![SpendInput { note: in_note, nsk, merkle_proof: proof }],
        outputs: vec![OutputNote { note: out }],
        fee: 0,
        fee_asset: fr(1),
    };
    match verify_transfer(&witness) {
        Err(TransferError::AssetNotConserved { .. }) => {}
        other => panic!("expected AssetNotConserved (cross-asset mint), got {other:?}"),
    }
}

#[test]
fn invalid_fee_in_unfunded_asset_rejected() {
    // Fee charged in an asset that no input/output touches: you cannot pay a fee in an asset you
    // did not bring. Guards the "fee in an absent asset" hole (0 != fee for that asset).
    let nsk = fr(5);
    let owner = owner_from_nsk(&nsk);
    let in_note = Note::new(100, owner, fr(1), fr(900));
    let mut tree = PoseidonMerkleTree::empty(DEPTH);
    tree.insert(&fr(9), &in_note.commitment());
    let anchor = tree.root();
    let proof = tree.inclusion_proof(&fr(9));

    let out = Note::new(100, owner_from_nsk(&fr(6)), fr(1), fr(901));
    let witness = TransferWitness {
        anchor,
        inputs: vec![SpendInput { note: in_note, nsk, merkle_proof: proof }],
        outputs: vec![OutputNote { note: out }],
        fee: 5,
        fee_asset: fr(2), // asset 2 appears in no note
    };
    match verify_transfer(&witness) {
        Err(TransferError::AssetNotConserved { .. }) => {}
        other => panic!("expected AssetNotConserved (fee in unfunded asset), got {other:?}"),
    }
}

#[test]
fn valid_multi_asset_transfer_passes() {
    // A legitimate two-asset basket in a single proof: asset 1 (100 in -> 95 out + 5 fee) and
    // asset 2 (70 in -> 70 out, no fee). Per-asset conservation must ACCEPT this.
    let nsk_a = fr(11);
    let nsk_b = fr(22);
    let in_a = Note::new(100, owner_from_nsk(&nsk_a), fr(1), fr(7001));
    let in_b = Note::new(70, owner_from_nsk(&nsk_b), fr(2), fr(7002));

    let mut tree = PoseidonMerkleTree::empty(DEPTH);
    tree.insert(&fr(3), &in_a.commitment());
    tree.insert(&fr(4), &in_b.commitment());
    let anchor = tree.root();
    let proof_a = tree.inclusion_proof(&fr(3));
    let proof_b = tree.inclusion_proof(&fr(4));

    let out_a = Note::new(95, owner_from_nsk(&fr(33)), fr(1), fr(8001));
    let out_b = Note::new(70, owner_from_nsk(&fr(44)), fr(2), fr(8002));

    let witness = TransferWitness {
        anchor,
        inputs: vec![
            SpendInput { note: in_a, nsk: nsk_a, merkle_proof: proof_a },
            SpendInput { note: in_b, nsk: nsk_b, merkle_proof: proof_b },
        ],
        outputs: vec![OutputNote { note: out_a }, OutputNote { note: out_b }],
        fee: 5,
        fee_asset: fr(1), // fee charged in asset 1
    };
    let public = verify_transfer(&witness).expect("balanced multi-asset transfer must pass");
    assert_eq!(public.fee_asset, fr(1));
    assert_eq!(public.nullifiers.len(), 2);
}

#[test]
fn wire_round_trip_and_pub_values_codec() {
    let f = valid_fixture();

    // Witness -> wire JSON -> witness, then verify the reconstructed witness.
    let wire: WireWitness = (&f.witness).into();
    let json = serde_json::to_string(&wire).unwrap();
    let wire_back: WireWitness = serde_json::from_str(&json).unwrap();
    let witness_back: TransferWitness = (&wire_back).into();
    let public = verify_transfer(&witness_back).expect("round-tripped witness must pass");

    // Public values -> sol bytes -> public values.
    let pv = ShieldedTransferPublicValues::from(&public);
    use alloy_sol_types::SolType;
    let bytes = ShieldedTransferPublicValues::abi_encode(&pv);
    let pv_back = ShieldedTransferPublicValues::abi_decode(&bytes).unwrap();
    let public_back: zk_shielded_lib::TransferPublic = (&pv_back).into();

    assert_eq!(public, public_back);
    assert_eq!(public_back.nullifiers, f.expected_nf);
    assert_eq!(public_back.output_cms, f.expected_cm);
}

#[test]
fn emit_sample_public_values() {
    let f = valid_fixture();
    let public = verify_transfer(&f.witness).unwrap();
    println!("--- sample shielded-transfer public values (hex) ---");
    println!("anchor       = 0x{:064x}", public.anchor);
    for (i, n) in public.nullifiers.iter().enumerate() {
        println!("nullifier[{i}] = 0x{:064x}", n);
    }
    for (i, c) in public.output_cms.iter().enumerate() {
        println!("outputCm[{i}]  = 0x{:064x}", c);
    }
    println!("fee          = {}", public.fee);

    // Also emit the wire JSON for the host script's default witness fixture.
    let wire: WireWitness = (&f.witness).into();
    println!("--- wire witness JSON ---");
    println!("{}", serde_json::to_string(&wire).unwrap());
}

//! Host driver for the general private state-transition zkVM program (M5).
//!
//! Modes:
//!   --mode execute   run the transition constraints inside the zkVM (no proof); cross-check
//!                    the committed public values against a native `verify_transition`.
//!   --mode prove     generate + verify an SP1 core proof.
//!   --mode groth16   generate + verify a Groth16-over-BN254 proof and SAVE a fixture
//!                    (proof bytes, public values, vkey) for cross-repo JVM verification.
//!   --mode plonk     generate + verify a PLONK-over-BN254 proof.
//!
//! GPU proving: set `SP1_PROVER=cuda` (the bundled `cuda` feature). CPU is the default.
//!
//! By default it runs a bundled valid 1-in/1-out transition (deduct a fee from a shielded
//! balance). Pass `--witness <file.json>` to drive a custom witness (wire JSON).
//!
//! Example:
//!   RUST_LOG=info cargo run --release -- --mode execute
//!   SP1_PROVER=cuda RUST_LOG=info cargo run --release -- --mode groth16

use alloy_sol_types::SolType;
use clap::Parser;
use num_bigint::BigUint;
use poseidon_bn254::merkle::PoseidonMerkleTree;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Stdin,
};
use std::fs;
use zk_jlvm_shielded_lib::pub_values::JlvmTransitionPublicValues;
use zk_jlvm_shielded_lib::wire::WireWitness;
use zk_jlvm_shielded_lib::{
    note_commitment, owner_from_nsk, verify_transition, TransitionPublic, TransitionWitness,
};

const SHIELDED_ELF: Elf = include_elf!("constellation-metagraph-sdk-confidential-state-program");

const DEPTH: usize = 8;

fn fr(n: u64) -> BigUint {
    BigUint::from(n)
}

/// The bundled, valid 1-in / 1-out transition used when no `--witness` file is given: a shielded
/// note holding `{"balance":100,"bids":[]}` is spent to apply "deduct event.amount from balance".
fn default_witness() -> TransitionWitness {
    let nsk = fr(111);
    let owner = owner_from_nsk(&nsk);
    let rho = fr(7001);
    let old_state = r#"{"balance":100,"bids":[]}"#;

    let cm = note_commitment(old_state, &owner, &rho).expect("commit old note");
    let mut tree = PoseidonMerkleTree::empty(DEPTH);
    tree.insert(&fr(5), &cm);
    let anchor = tree.root();
    let proof = tree.inclusion_proof(&fr(5));

    TransitionWitness {
        anchor,
        old_state_json: old_state.to_string(),
        owner,
        nsk,
        rho,
        merkle_proof: proof,
        effect_expr_json:
            r#"{"merge":[{"var":"state"},{"balance":{"-":[{"var":"state.balance"},{"var":"event.amount"}]}}]}"#
                .to_string(),
        event_json: r#"{"amount":30}"#.to_string(),
        new_owner: owner_from_nsk(&fr(222)),
        new_rho: fr(8001),
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// execute | prove | groth16 | plonk
    #[arg(long, default_value = "execute")]
    mode: String,
    /// Optional path to a wire-JSON witness file (overrides the bundled default).
    #[arg(long)]
    witness: Option<String>,
    /// Where to save the groth16 fixture (groth16 mode only).
    #[arg(long, default_value = "fixtures/transition_groth16_fixture.json")]
    fixture_out: String,
}

fn print_public(label: &str, p: &TransitionPublic) {
    println!("--- {label} ---");
    println!("anchor        = 0x{:064x}", p.anchor);
    println!("nullifier     = 0x{:064x}", p.nullifier);
    println!("newCommitment = 0x{:064x}", p.new_commitment);
    println!("exprHash      = 0x{}", hex::encode(p.expr_hash));
}

fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();
    let args = Args::parse();

    // Build the witness (file or bundled default).
    let witness: TransitionWitness = match &args.witness {
        Some(path) => {
            let json = fs::read_to_string(path).expect("read witness file");
            let wire: WireWitness = serde_json::from_str(&json).expect("parse witness JSON");
            (&wire).into()
        }
        None => default_witness(),
    };

    // Native expectation (the same constraint logic the guest runs).
    let native = verify_transition(&witness).expect("witness must be valid to drive the prover");
    print_public("native verify_transition (expected public values)", &native);

    let wire: WireWitness = (&witness).into();
    let witness_json = serde_json::to_string(&wire).unwrap();

    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write(&witness_json);

    match args.mode.as_str() {
        "execute" => {
            let (public_values, report) = client.execute(SHIELDED_ELF, stdin).run().unwrap();
            let pv = JlvmTransitionPublicValues::abi_decode(public_values.as_slice()).unwrap();
            let got: TransitionPublic = (&pv).into();
            print_public("zkVM-committed public values", &got);
            assert_eq!(got, native, "zkVM public values != native");
            println!(
                "zkVM result matches native. cycles: {}",
                report.total_instruction_count()
            );
        }
        "prove" => {
            let pk = client.setup(SHIELDED_ELF).expect("setup");
            let proof = client.prove(&pk, stdin).run().expect("prove");
            client.verify(&proof, pk.verifying_key(), None).expect("verify");
            println!("Core proof generated AND verified.");
            println!("public values: 0x{}", hex::encode(proof.public_values.as_slice()));
        }
        "groth16" | "plonk" => {
            let pk = client.setup(SHIELDED_ELF).expect("setup");
            let req = client.prove(&pk, stdin);
            let proof = if args.mode == "groth16" {
                req.groth16().run()
            } else {
                req.plonk().run()
            }
            .expect("wrap prove");
            client.verify(&proof, pk.verifying_key(), None).expect("verify");

            let pv = JlvmTransitionPublicValues::abi_decode(proof.public_values.as_slice()).unwrap();
            let got: TransitionPublic = (&pv).into();
            assert_eq!(got, native, "proven public values != native");

            let vkey = pk.verifying_key().bytes32();
            let pub_hex = format!("0x{}", hex::encode(proof.public_values.as_slice()));
            let proof_hex = format!("0x{}", hex::encode(proof.bytes()));
            println!("{} proof generated AND verified (public values match native).", args.mode);
            println!("vkey:          {vkey}");
            println!("public values: {pub_hex}");
            println!("proof bytes:   {proof_hex}");

            if args.mode == "groth16" {
                let fixture = serde_json::json!({
                    "scheme": "groth16-bn254",
                    "vkey": vkey,
                    "publicValues": pub_hex,
                    "proof": proof_hex,
                    "witness": serde_json::from_str::<serde_json::Value>(&witness_json).unwrap(),
                });
                fs::write(&args.fixture_out, serde_json::to_string_pretty(&fixture).unwrap())
                    .expect("write fixture");
                println!("groth16 fixture saved to {}", args.fixture_out);
            }
        }
        m => {
            eprintln!("unknown mode: {m} (use execute|prove|groth16|plonk)");
            std::process::exit(1);
        }
    }
}

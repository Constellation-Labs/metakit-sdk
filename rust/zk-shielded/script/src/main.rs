//! Host driver for the shielded-transfer zkVM program (M4).
//!
//! Modes:
//!   --mode execute   run the transfer constraints inside the zkVM (no proof); cross-check
//!                    the committed public values against a native `verify_transfer`.
//!   --mode prove     generate + verify an SP1 core proof.
//!   --mode groth16   generate + verify a Groth16-over-BN254 proof and SAVE a fixture
//!                    (proof bytes, public values, vkey) for cross-repo verification in
//!                    metakit's JVM Groth16 verifier.
//!   --mode plonk     generate + verify a PLONK-over-BN254 proof.
//!
//! GPU proving: set `SP1_PROVER=cuda` (needs the sp1-sdk `cuda` feature). CPU is default.
//!
//! By default it runs the bundled valid 2-in/2-out witness. Pass `--witness <file.json>`
//! to drive a custom witness (wire JSON, as emitted by the native tests).
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
use zk_shielded_lib::pub_values::ShieldedTransferPublicValues;
use zk_shielded_lib::wire::WireWitness;
use zk_shielded_lib::{
    owner_from_nsk, verify_transfer, Note, OutputNote, SpendInput, TransferPublic, TransferWitness,
};

const SHIELDED_ELF: Elf = include_elf!("zk-shielded-program");

const DEPTH: usize = 8;

fn fr(n: u64) -> BigUint {
    BigUint::from(n)
}

/// The bundled, valid 2-in / 2-out transfer used when no `--witness` file is given.
fn default_witness() -> TransferWitness {
    let asset = fr(1);
    let (nsk_a, nsk_b) = (fr(111), fr(222));
    let in_a = Note::new(100, owner_from_nsk(&nsk_a), asset.clone(), fr(7001));
    let in_b = Note::new(50, owner_from_nsk(&nsk_b), asset.clone(), fr(7002));

    let mut tree = PoseidonMerkleTree::empty(DEPTH);
    tree.insert(&fr(3), &in_a.commitment());
    tree.insert(&fr(200), &in_b.commitment());
    let anchor = tree.root();
    let proof_a = tree.inclusion_proof(&fr(3));
    let proof_b = tree.inclusion_proof(&fr(200));

    let out_c = Note::new(120, owner_from_nsk(&fr(333)), asset.clone(), fr(8001));
    let out_d = Note::new(25, owner_from_nsk(&fr(444)), asset.clone(), fr(8002));

    TransferWitness {
        anchor,
        inputs: vec![
            SpendInput { note: in_a, nsk: nsk_a, merkle_proof: proof_a },
            SpendInput { note: in_b, nsk: nsk_b, merkle_proof: proof_b },
        ],
        outputs: vec![OutputNote { note: out_c }, OutputNote { note: out_d }],
        fee: 5,
        fee_asset: asset, // fee charged in the (single) transfer asset
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
    #[arg(long, default_value = "fixtures/shielded_groth16_fixture.json")]
    fixture_out: String,
}

fn print_public(label: &str, p: &TransferPublic) {
    println!("--- {label} ---");
    println!("anchor       = 0x{:064x}", p.anchor);
    for (i, n) in p.nullifiers.iter().enumerate() {
        println!("nullifier[{i}] = 0x{:064x}", n);
    }
    for (i, c) in p.output_cms.iter().enumerate() {
        println!("outputCm[{i}]  = 0x{:064x}", c);
    }
    println!("fee          = {}", p.fee);
}

fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();
    let args = Args::parse();

    // Build the witness (file or bundled default).
    let witness: TransferWitness = match &args.witness {
        Some(path) => {
            let json = fs::read_to_string(path).expect("read witness file");
            let wire: WireWitness = serde_json::from_str(&json).expect("parse witness JSON");
            (&wire).into()
        }
        None => default_witness(),
    };

    // Native expectation (the same constraint logic the guest runs).
    let native = verify_transfer(&witness).expect("witness must be valid to drive the prover");
    print_public("native verify_transfer (expected public values)", &native);

    let wire: WireWitness = (&witness).into();
    let witness_json = serde_json::to_string(&wire).unwrap();

    let client = ProverClient::from_env();
    let mut stdin = SP1Stdin::new();
    stdin.write(&witness_json);

    match args.mode.as_str() {
        "execute" => {
            let (public_values, report) = client.execute(SHIELDED_ELF, stdin).run().unwrap();
            let pv = ShieldedTransferPublicValues::abi_decode(public_values.as_slice()).unwrap();
            let got: TransferPublic = (&pv).into();
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

            let pv = ShieldedTransferPublicValues::abi_decode(proof.public_values.as_slice()).unwrap();
            let got: TransferPublic = (&pv).into();
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

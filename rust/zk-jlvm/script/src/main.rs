//! Host driver for the JLVM zkVM program.
//!
//! Modes:
//!   --mode execute   run the JLVM inside the zkVM (no proof); cross-check vs native jlvm-core
//!   --mode prove     generate + verify an SP1 core proof
//!   --mode groth16   generate + verify a Groth16-over-BN254 proof (EVM/JVM-verifiable)
//!   --mode plonk     generate + verify a PLONK-over-BN254 proof
//!
//! GPU proving: set `SP1_PROVER=cuda` (needs the sp1-sdk `cuda` feature). CPU is the default.
//!
//! Example:
//!   RUST_LOG=info cargo run --release -- --mode execute
//!   SP1_PROVER=cuda RUST_LOG=info cargo run --release -- --mode groth16

use alloy_primitives::{keccak256, B256};
use alloy_sol_types::SolType;
use clap::Parser;
use zk_jlvm_lib::JlvmPublicValues;
use sp1_sdk::{
    blocking::{ProveRequest, Prover, ProverClient},
    include_elf, Elf, HashableKey, ProvingKey, SP1Stdin,
};

const JLVM_ELF: Elf = include_elf!("zk-jlvm-program");

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// execute | prove | groth16 | plonk
    #[arg(long, default_value = "execute")]
    mode: String,
    /// JSON Logic expression
    #[arg(
        long,
        default_value = r#"{"if": [{">": [{"var": "amount"}, 100]}, "premium", "standard"]}"#
    )]
    expr: String,
    /// JSON data context
    #[arg(long, default_value = r#"{"amount": 150}"#)]
    data: String,
}

fn main() {
    sp1_sdk::utils::setup_logger();
    dotenv::dotenv().ok();
    let args = Args::parse();

    let client = ProverClient::from_env();

    let mut stdin = SP1Stdin::new();
    stdin.write(&args.expr);
    stdin.write(&args.data);

    // Compute the expected result natively (host jlvm-core) for cross-checking the zkVM.
    let native = jlvm_core::evaluate_to_canonical(&args.expr, &args.data);
    println!("expr: {}", args.expr);
    println!("data: {}", args.data);
    match &native {
        Ok(b) => println!("native canonical output: {}", String::from_utf8_lossy(b)),
        Err(e) => println!("native eval error: {}", e),
    }
    let expected_output_hash = match &native {
        Ok(b) => keccak256(b.as_slice()),
        Err(_) => B256::ZERO,
    };

    match args.mode.as_str() {
        "execute" => {
            let (public_values, report) = client.execute(JLVM_ELF, stdin).run().unwrap();
            let pv = JlvmPublicValues::abi_decode(public_values.as_slice(), true).unwrap();
            println!("--- executed in the zkVM ---");
            println!("ok:         {}", pv.ok);
            println!("exprHash:   {}", pv.exprHash);
            println!("dataHash:   {}", pv.dataHash);
            println!("outputHash: {}", pv.outputHash);
            assert_eq!(pv.exprHash, keccak256(args.expr.as_bytes()), "exprHash mismatch");
            assert_eq!(pv.dataHash, keccak256(args.data.as_bytes()), "dataHash mismatch");
            assert_eq!(pv.outputHash, expected_output_hash, "zkVM output != native output");
            println!(
                "zkVM result matches native. cycles: {}",
                report.total_instruction_count()
            );
        }
        "prove" => {
            let pk = client.setup(JLVM_ELF).expect("setup");
            let proof = client.prove(&pk, stdin).run().expect("prove");
            client.verify(&proof, pk.verifying_key(), None).expect("verify");
            println!("Core proof generated AND verified.");
            println!(
                "public values: 0x{}",
                hex::encode(proof.public_values.as_slice())
            );
        }
        "groth16" | "plonk" => {
            let pk = client.setup(JLVM_ELF).expect("setup");
            let req = client.prove(&pk, stdin);
            let proof = if args.mode == "groth16" {
                req.groth16().run()
            } else {
                req.plonk().run()
            }
            .expect("wrap prove");
            client.verify(&proof, pk.verifying_key(), None).expect("verify");

            let pv = JlvmPublicValues::abi_decode(proof.public_values.as_slice(), true).unwrap();
            assert_eq!(pv.outputHash, expected_output_hash, "proven output != native output");

            println!("{} proof generated AND verified (output matches native).", args.mode);
            println!("vkey:          {}", pk.verifying_key().bytes32());
            println!(
                "public values: 0x{}",
                hex::encode(proof.public_values.as_slice())
            );
            println!("proof bytes:   0x{}", hex::encode(proof.bytes()));
        }
        m => {
            eprintln!("unknown mode: {} (use execute|prove|groth16|plonk)", m);
            std::process::exit(1);
        }
    }
}

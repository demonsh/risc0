use std::fs;
use std::path::PathBuf;
use sha_methods2::HASH_ID;
use risc0_zkvm::{
    serde::{from_slice, to_vec},
    SessionFlatReceipt, SessionReceipt};


fn main() {
    let receipt_str: String = "./receipts.bin".to_string();

    // let receipt_file:Vec<u8> = std::fs::read(receipt_str).unwrap();

    // let receipt: SessionFlatReceipt = bincode::deserialize::<SessionFlatReceipt>(&receipt_file).unwrap();
    let receipt: SessionFlatReceipt = from_slice(&fs::read(receipt_str).unwrap()).unwrap();
    // let receipt: SessionFlatReceipt =
    //     bincode::deserialize(&fs::read(PathBuf::from(receipt_str)).unwrap())
    //         .expect("Failed to read input file");

    receipt
        .verify(HASH_ID.into())
        .expect("receipt verification failed");

    println!("I provably know somethign");
}

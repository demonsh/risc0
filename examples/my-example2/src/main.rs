// Copyright 2023 RISC Zero, Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use bincode::serialize;
use clap::{Arg, Command};
use hex_literal::hex;
use k256::ecdsa::{signature::Signer, Signature, SigningKey, VerifyingKey};
use mjson_core::Outputs;
// use rand_core::OsRng;
use serde::{Deserialize, Serialize};
use risc0_zkvm::{
    serde::{from_slice, to_vec},
    sha::{Impl, Sha256}, // Digest
    Executor,
    ExecutorEnv,
    SessionReceipt,
    SessionFlatReceipt,
};
use sha_methods2::{HASH_ELF, HASH_ID, HASH_RUST_CRYPTO_ELF};

/// Hash the given bytes, returning the digest and a [SessionReceipt] that can
/// be used to verify that the that the hash was computed correctly (i.e. that
/// the Prover knows a preimage for the given SHA-256 hash)
///
/// Select which method to use with `use_rust_crypto`.
/// HASH_ELF uses the risc0_zkvm::sha interface for hashing.
/// HASH_RUST_CRYPTO_ELF uses RustCrypto's [sha2] crate, patched to use the RISC
/// Zero accelerator. See `src/methods/guest/Cargo.toml` for the patch
/// definition, which can be used to enable SHA-256 accelerrator support
/// everywhere the [sha2] crate is used.
fn provably_hash(
    input: &str,
    signature: &Signature,
    verifying_key: &VerifyingKey,
    use_rust_crypto: bool,
) -> Box<dyn SessionReceipt> {
    let operation = 0;
    let value = 50;

    let env = ExecutorEnv::builder()
        .add_input(&to_vec(input).unwrap())
        .add_input(&to_vec(&(verifying_key.to_encoded_point(true), signature)).unwrap())
        .add_input(&to_vec(&(operation)).unwrap())
        .add_input(&to_vec(&(value)).unwrap())
        .build()
        .unwrap();

    let elf = if use_rust_crypto {
        println!("HASH_RUST_CRYPTO_ELF");
        HASH_RUST_CRYPTO_ELF
    } else {
        println!("HASH_ELF");
        HASH_ELF
    };

    let mut exec = Executor::from_elf(env, elf).unwrap();
    let session = exec.run().unwrap();
    let receipt = session.prove().unwrap();

    receipt
}

fn main() {
    // read key from string
    // let key_string =
    // "ac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80";
    // let key_bytes = hex::decode(key_string).expect("Failed to decode signing key
    // from hex"); print key_bytes
    // println!("Key Bytes: {:?}", key_bytes);

    // let signing_key = SigningKey::from_bytes(&key_bytes.to_bytes()).unwrap();
    let signing_key = SigningKey::from_bytes(
        &hex!("4c0883a69102937d6231471b5dbb6204fe5129617082792ae468d01a3f362318").into(),
    )
    .unwrap();
    // print key
    // let signing_key = SigningKey::random(&mut OsRng);
    println!("Private Key: {}", hex::encode(signing_key.to_bytes()));
    let verifying_key = signing_key.verifying_key();
    println!("Public Key: {}", verifying_key.to_encoded_point(true));

    // Generate a random secp256k1 keypair and sign the message.
    // let signing_key = SigningKey::random(&mut OsRng); // Serialize with
    // `::to_bytes()`
    // let message = b"This is a message that will be signed, and verified within
    // the zkVM";
    // let signature: Signature = signing_key.sign(message);

    // print signature
    // println!("Signature: {:?}", signature);

    // Parse command line
    let data = include_str!("../../json/res/example.json");
    let matches = Command::new("hash")
        .arg(Arg::new("message").default_value(data))
        .get_matches();
    let digest = Impl::hash_bytes(&data.as_bytes());
    let signature: Signature = signing_key.sign(digest.as_bytes());

    let message = matches.get_one::<String>("message").unwrap();

    // Prove hash the message.
    let receipt = provably_hash(message, &signature, signing_key.verifying_key(), false);

    let outputs: Outputs = from_slice(receipt.get_journal()).unwrap();

    // let (proven_val, digest, encoded_verifying_key, operation) =
    //     from_slice::<(u32, Vec<u8>, EncodedPoint, bool),
    // _>(receipt.get_journal())         .unwrap()
    //         .try_into()
    //         .unwrap();

    // Verify the receipt, ensuring the prover knows a valid SHA-256 preimage.
    receipt
        .verify(HASH_ID.into())
        .expect("receipt verification failed");

    // let s = String::from_utf8(digest).expect("Found invalid UTF-8");
    let hex_str = hex::encode(&outputs.digest);
    println!("I provably know data whose SHA-256 hash is {:?}", hex_str);
    println!("I verificaiton key {}", outputs.encoded_verifying_key);
    println!("proven_val {}", outputs.proven_val);
    println!("operation {}", outputs.operation);
    println!("result {}", outputs.result);

    // receipt to SessionFlatReceipt

    // let serialized = bincode::serialize(&rece).unwrap();

    let file: () = match std::fs::write("./receipts.bin",  receipt.encode()) {
        Ok(file) => file,
        Err(error) => panic!("Unable to write file: {:?}", error),
    };

}

#[cfg(test)]
mod tests {
    use sha_methods::{HASH_ID, HASH_RUST_CRYPTO_ID};

    #[test]
    fn hash_abc() {
        let (digest, receipt) = super::provably_hash("abc", false);
        receipt.verify(HASH_ID.into()).unwrap();
        assert_eq!(
            hex::encode(digest.as_bytes()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "We expect to match the reference SHA-256 hash of the standard test value 'abc'"
        );
    }

    #[test]
    fn hash_abc_rust_crypto() {
        let (digest, receipt) = super::provably_hash("abc", true);
        receipt.verify(HASH_RUST_CRYPTO_ID.into()).unwrap();
        assert_eq!(
            hex::encode(digest.as_bytes()),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "We expect to match the reference SHA-256 hash of the standard test value 'abc'"
        );
    }
}

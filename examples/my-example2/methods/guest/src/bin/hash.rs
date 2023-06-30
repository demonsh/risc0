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

#![no_main]

use json::parse;
use k256::{
    ecdsa::{signature::Verifier, Signature, VerifyingKey},
    EncodedPoint,
};
use mjson_core::Outputs;
use risc0_zkvm::{
    guest::env,
    sha::{Impl, Sha256},
};

risc0_zkvm::guest::entry!(main);

// Example of using the risc0_zkvm::sha module to hash data.
pub fn main() {
    let data: String = env::read();

    let jsonData = parse(&data).unwrap();
    let proven_val = jsonData["critical_data"].as_u32().unwrap();
    // env::commit(&proven_val);
    // let sig: String = env::read();
    let digest = Impl::hash_bytes(&data.as_bytes());
    // env::commit(&digest.as_bytes());

    // Decode the verifying key, message, and signature from the inputs.
    let (encoded_verifying_key, signature): (EncodedPoint, Signature) = env::read();
    let verifying_key = VerifyingKey::from_encoded_point(&encoded_verifying_key).unwrap();

    // Verify the signature, panicking if verification fails.
    verifying_key
        .verify(&digest.as_bytes(), &signature)
        .expect("ECDSA signature verification failed");
    // Commit to the journal the verifying key and messge that was signed.
    // env::commit(&(encoded_verifying_key));

    let operation: u32 = env::read();
    let value: u32 = env::read();

    let mut resul: bool = false;
    match operation {
        0 => {
            // equal
            // proven_val is grater than 0
            if proven_val > value {
                resul = true;
            }
        }
        1 => {
            // less than
            // proven_val is less than 0
            if proven_val < value {
                resul = true;
            }
        }
        _ => panic!("Unknown operation"),
    }
    // env::commit(&resul);

    let out = Outputs {
        proven_val: proven_val,
        digest: digest.as_bytes().to_vec(),
        encoded_verifying_key: encoded_verifying_key,
        operation: operation,
        result: resul,
    };
    env::commit(&out);
}

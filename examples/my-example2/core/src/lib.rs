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

use k256::EncodedPoint;
// use risc0_zkvm::sha::Digest;
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Outputs {
    pub proven_val: u32,
    pub digest: Vec<u8>,
    pub encoded_verifying_key: EncodedPoint,
    pub operation: u32,
    pub result: bool,
}

// let (proven_val, digest, encoded_verifying_key, operation) =
//     from_slice::<(u32, Vec<u8>, EncodedPoint, bool),
// _>(receipt.get_journal())         .unwrap()
//         .try_into()
//         .unwrap();

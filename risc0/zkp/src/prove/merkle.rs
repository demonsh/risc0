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

use alloc::vec::Vec;

#[allow(unused_imports)]
use log::debug;

use crate::{
    core::digest::Digest,
    hal::{Buffer, Hal},
    merkle::MerkleTreeParams,
    prove::write_iop::WriteIOP,
};

pub struct MerkleTreeProver<H: Hal> {
    params: MerkleTreeParams,

    // The retained matrix of values
    matrix: H::Buffer<H::Elem>,

    // A heap style array where node N has children 2*N and 2*N+1.  The size of
    // this buffer is (1 << (layers + 1)) and begins at offset 1 (zero is unused
    // to make indexing nicer).
    nodes: Vec<Digest>,

    // The root value
    root: Digest,
}

impl<H: Hal> MerkleTreeProver<H> {
    /// Generate a merkle tree from a matrix of values.
    ///
    /// The proofs will prove a single 'column' of values in the tree at a
    /// certain row. Layout is presumed to be packed row-major.
    /// The number of queries represents the expected # of queries and
    /// determines the size of the 'top' layer. It is important that the
    /// verifier is constructed with identical size parameters, including # of
    /// queries, or verification may fail.
    ///
    /// matrix: `rows * cols`
    /// rows: `domain = steps * INV_RATE`, `steps` is always a power of 2.
    /// cols: `count = circuit_cols`
    #[tracing::instrument(name = "MerkleTreeProver", skip_all)]
    pub fn new(
        hal: &H,
        matrix: &H::Buffer<H::Elem>,
        rows: usize,
        cols: usize,
        queries: usize,
    ) -> Self {
        assert_eq!(matrix.size(), rows * cols);
        let params = MerkleTreeParams::new(rows, cols, queries);
        // Allocate nodes
        let nodes = hal.alloc_digest("nodes", rows * 2);
        // SHA-256 hash each column
        hal.hash_rows(&nodes.slice(rows, rows), matrix);
        // For each layer, sha up the layer below
        tracing::info_span!("hash_fold").in_scope(|| {
            for i in (0..params.layers).rev() {
                let layer_size = 1 << i;
                hal.hash_fold(&nodes, layer_size * 2, layer_size);
            }
        });
        let mut nodes_host = Vec::with_capacity(nodes.size());
        nodes.view(|view| {
            nodes_host.extend_from_slice(view);
        });
        let root = nodes_host[1];
        MerkleTreeProver {
            params,
            matrix: matrix.clone(),
            nodes: nodes_host,
            root,
        }
    }

    /// Write the 'top' of the merkle tree and commit to the root.
    pub fn commit(&self, iop: &mut WriteIOP<H::Field, H::Rng>) {
        let top_size = self.params.top_size;
        iop.write_pod_slice(&self.nodes[top_size..top_size * 2]);
        iop.commit(self.root());
    }

    /// Get the root digest of the tree.
    pub fn root(&self) -> &Digest {
        &self.root
    }

    /// Generate a proof at a given index, and return the values at that column.
    ///
    /// The format of the proof is always:
    /// 1) The column itself
    /// 2) The 'other' digests up to the top.
    ///
    /// It is presumed the verifier is given the index of the row from other
    /// parts of the protocol, and verification will of course fail if the
    /// wrong row is specified.
    pub fn prove(&self, hal: &H, iop: &mut WriteIOP<H::Field, H::Rng>, idx: usize) -> Vec<H::Elem> {
        assert!(idx < self.params.row_size);
        let mut out = Vec::with_capacity(self.params.col_size);
        if hal.has_unified_memory() {
            self.matrix.view(|view| {
                for i in 0..self.params.col_size {
                    out.push(view[idx + i * self.params.row_size]);
                }
            });
        } else {
            let sample = hal.alloc_elem("sample", self.params.col_size);
            hal.gather_sample(
                &sample,
                &self.matrix,
                idx,
                self.params.col_size,
                self.params.row_size,
            );
            sample.view(|view| {
                out.extend_from_slice(view);
            });
        }
        iop.write_field_elem_slice::<H::Elem>(out.as_slice());
        let mut idx = idx + self.params.row_size;
        while idx >= 2 * self.params.top_size {
            let low_bit = idx % 2;
            idx /= 2;
            let other_idx = 2 * idx + (1 - low_bit);
            iop.write_pod_slice(&[self.nodes[other_idx]]);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use rand::Rng;
    use risc0_core::field::{
        baby_bear::{BabyBear, BabyBearElem, BabyBearExtElem},
        Elem,
    };

    use super::*;
    use crate::{
        adapter::{MixState, PolyExt},
        core::{
            hash::{
                poseidon::PoseidonHashSuite,
                sha::{cpu::Impl as CpuImpl, Sha256HashSuite},
                HashSuite, Rng as _,
            },
            log2_ceil,
        },
        hal::cpu::CpuHal,
        verify::{merkle::MerkleTreeVerifier, read_iop::ReadIOP, CpuVerifyHal, VerificationError},
    };

    struct MockCircuit {}

    impl PolyExt<BabyBear> for MockCircuit {
        fn poly_ext(
            &self,
            _mix: &BabyBearExtElem,
            _u: &[BabyBearExtElem],
            _args: &[&[BabyBearElem]],
        ) -> MixState<BabyBearExtElem> {
            unimplemented!()
        }
    }

    type ShaSuite = Sha256HashSuite<BabyBear, CpuImpl>;
    type PoseidonSuite = PoseidonHashSuite;
    type VerifierHal<'a, HS> = CpuVerifyHal<'a, BabyBear, HS, MockCircuit>;

    fn init_prover<H: Hal>(
        hal: &H,
        rows: usize,
        cols: usize,
        queries: usize,
    ) -> MerkleTreeProver<H> {
        // Initialize a prover with leaves 0..size
        let size: u32 = (rows * cols) as u32;
        let mut data: Vec<H::Elem> = Vec::new();
        for val in 0..size {
            data.push(H::Elem::from_u64((u32::MAX / 2) as u64 - val as u64));
        }
        let matrix = hal.copy_from_elem("matrix", data.as_slice());

        MerkleTreeProver::new(hal, &matrix, rows, cols, queries)
    }

    fn bad_row_access<HS: HashSuite<BabyBear>>(rows: usize, cols: usize, queries: usize) {
        let hal = CpuHal::<BabyBear, HS>::new();
        let prover = init_prover(&hal, rows, cols, queries);
        let mut iop = WriteIOP::<BabyBear, HS::Rng>::new();
        prover.prove(&hal, &mut iop, rows);
    }

    fn bad_row_access_all(rows: usize, cols: usize, queries: usize) {
        bad_row_access::<ShaSuite>(rows, cols, queries);
        bad_row_access::<PoseidonSuite>(rows, cols, queries);
    }

    fn possibly_bad_verify<HS: HashSuite<BabyBear>>(
        rows: usize,
        cols: usize,
        queries: usize,
        bad_query: usize,
        manipulate_proof: bool,
    ) {
        let hal = CpuHal::<BabyBear, HS>::new();
        let prover = init_prover(&hal, rows, cols, queries);

        let mut iop = WriteIOP::<BabyBear, HS::Rng>::new();
        prover.commit(&mut iop);
        for _query in 0..queries {
            let r_idx = iop.rng.random_bits(log2_ceil(rows)) as usize;
            let col = prover.prove(&hal, &mut iop, r_idx);
            for c_idx in 0..cols {
                assert_eq!(
                    col[c_idx],
                    BabyBearElem::from_u64((u32::MAX / 2) as u64 - ((r_idx + c_idx * rows) as u64))
                );
            }
        }
        if manipulate_proof {
            let mut rng = rand::thread_rng();
            let manip_idx = rng.gen::<usize>() % iop.proof.len();
            iop.proof[manip_idx] ^= 1;
        }
        let mut r_iop = ReadIOP::<BabyBear, HS::Rng>::new(&iop.proof);
        let verifier = MerkleTreeVerifier::<VerifierHal<HS>>::new(&mut r_iop, rows, cols, queries);
        assert_eq!(verifier.root(), prover.root());
        let mut err = false;
        for query in 0..queries {
            let r_idx = r_iop.random_bits(log2_ceil(rows)) as usize;
            if query == bad_query {
                if rows == 1 {
                    assert!(false, "Cannot test for bad query if there is only one row");
                }
                let r_idx = (r_idx + 1) % rows;
                let verification = verifier.verify(&mut r_iop, r_idx);
                match verification {
                    Ok(_) => assert!(
                        false,
                        "Merkle tree wrongly passed verify when tested on the wrong row"
                    ),
                    Err(VerificationError::InvalidProof) => {}
                    Err(_) => assert!(
                        false,
                        "Merkle tree failed validation for an unexpected reason"
                    ),
                }
                err = true;
                break;
            }
            let col = verifier.verify(&mut r_iop, r_idx).unwrap();
            for c_idx in 0..cols {
                assert_eq!(
                    col[c_idx],
                    BabyBearElem::from((u32::MAX / 2) - ((r_idx + c_idx * rows) as u32))
                );
            }
        }
        if !err {
            r_iop.verify_complete();
        }
    }

    fn possibly_bad_verify_all(
        rows: usize,
        cols: usize,
        queries: usize,
        bad_query: usize,
        manipulate_proof: bool,
    ) {
        possibly_bad_verify::<ShaSuite>(rows, cols, queries, bad_query, manipulate_proof);
        possibly_bad_verify::<PoseidonSuite>(rows, cols, queries, bad_query, manipulate_proof);
    }

    fn randomize_sizes() -> (usize, usize, usize) {
        // Chooses random values of `rows`, `cols`, and `queries` such that:
        // `rows` is a power of 2
        // `cols` & `queries` have a wide distribution but tend to take small values
        let mut rng = rand::thread_rng();
        let rows = 1 << (rng.gen::<u8>() % 10);
        let cols = (rng.gen::<usize>() % (1 << (rng.gen::<u8>() % 10))) + 1;
        let queries = (rng.gen::<usize>() % (1 << (rng.gen::<u8>() % 10))) + 1;
        (rows, cols, queries)
    }

    #[test]
    #[should_panic(expected = "assertion failed: idx < self.params.row_size")]
    fn merkle_cpu_1_1_1_bad_row_access() {
        bad_row_access_all(1, 1, 1);
    }

    #[test]
    #[should_panic(expected = "assertion failed: idx < self.params.row_size")]
    fn merkle_cpu_4_4_2_bad_row_access() {
        bad_row_access_all(4, 4, 2);
    }

    #[test]
    #[should_panic(expected = "assertion failed: idx < self.params.row_size")]
    fn merkle_cpu_randomized_bad_row_access() {
        let (rows, cols, queries) = randomize_sizes();
        bad_row_access_all(rows, cols, queries);
    }

    #[test]
    fn merkle_cpu_1_1_1_verify() {
        // Test a complete verification with no bad queries (by setting bad_query out of
        // range)
        possibly_bad_verify_all(1, 1, 1, 4, false);
    }

    #[test]
    fn merkle_cpu_4_4_2_verify() {
        // Test a complete verification with no bad queries (by setting bad_query out of
        // range)
        possibly_bad_verify_all(4, 4, 2, 4, false);
    }

    #[test]
    fn merkle_cpu_randomized_verify() {
        for _rep in 0..100 {
            let (rows, cols, queries) = randomize_sizes();
            // Test a complete verification with no bad queries (by setting bad_query out of
            // range)
            possibly_bad_verify_all(rows, cols, queries, queries + 1, false);
        }
    }

    #[test]
    fn merkle_cpu_2_1_1_bad_query() {
        // n.b. since we test bad queries by incrementing the row, we can't test for a
        // bad query with rows == 1
        possibly_bad_verify_all(2, 1, 1, 0, false);
    }

    #[test]
    fn merkle_cpu_4_4_2_bad_query() {
        let mut rng = rand::thread_rng();
        let queries = 2;
        // Test a complete verification with a bad query
        let bad_query = rng.gen::<usize>() % queries;
        possibly_bad_verify_all(4, 4, queries, bad_query, false);
    }

    #[test]
    fn merkle_cpu_randomized_bad_query() {
        let mut rng = rand::thread_rng();
        let (rows, cols, queries) = randomize_sizes();
        // At least two rows are required to test querying an incorrect row
        let rows = if rows == 1 { 2 } else { rows };
        // Test a complete verification with a bad query
        let bad_query = rng.gen::<usize>() % queries;
        possibly_bad_verify_all(rows, cols, queries, bad_query, false);
    }

    #[test]
    #[should_panic]
    fn merkle_cpu_1_1_1_verify_manipulated() {
        for _rep in 0..50 {
            // Test a verification with a manipulated proof but no bad queries (by setting
            // bad_query out of range) Do this multiple times as the
            // manipulation location is random
            possibly_bad_verify_all(1, 1, 1, 2, true);
        }
    }

    #[test]
    #[should_panic]
    fn merkle_cpu_4_4_2_verify_manipulated() {
        for _rep in 0..50 {
            // Test a verification with a manipulated proof but no bad queries (by setting
            // bad_query out of range) Do this multiple times as the
            // manipulation location is random
            possibly_bad_verify_all(4, 4, 2, 4, true);
        }
    }

    #[test]
    #[should_panic]
    fn merkle_cpu_randomized_verify_manipulated() {
        for _rep in 0..50 {
            let (rows, cols, queries) = randomize_sizes();
            // Test a verification with a manipulated proof but no bad queries (by setting
            // bad_query out of range) Do this multiple times as the
            // manipulation location is random
            possibly_bad_verify_all(rows, cols, queries, queries + 1, true);
        }
    }
}

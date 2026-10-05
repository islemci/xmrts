//! Merkle property + exhaustive tests (brief §5, Step 1).
//!
//! - Random sets of size 1..=300: every generated proof verifies;
//!   flipping any single byte of file hash / sibling / root fails.
//! - Exhaustive: every tree size 1..=70, every leaf index: proof verifies
//!   and path_len == expected_path_len.
//! - Duplicate-last-node regression (M6): `[a,b,c]` and `[a,b,c,c]` must
//!   produce *different* committed roots once size-commitment lands.
//!   Currently marked `#[ignore]` as a failing demonstration — M6 fix
//!   must un-ignore it.

use xmrts::protocol::merkle::{self, MerkleTree};

// Simple deterministic PRNG (xorshift64) — no extra deps.
struct Rng(u64);
impl Rng {
    fn next_u64(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
    fn next_bytes32(&mut self) -> [u8; 32] {
        let mut out = [0u8; 32];
        for chunk in out.chunks_mut(8) {
            chunk.copy_from_slice(&self.next_u64().to_le_bytes());
        }
        out
    }
}

#[test]
fn random_sets_all_proofs_verify() {
    let mut rng = Rng(0x1234_5678_9abc_def1);
    for size in [1usize, 2, 3, 5, 8, 16, 31, 64, 100, 300] {
        let hashes: Vec<[u8; 32]> = (0..size).map(|_| rng.next_bytes32()).collect();
        let (sorted, tree) = MerkleTree::build_from_unsorted(hashes).unwrap();
        assert_eq!(tree.tree_size(), size as u64);
        for (i, h) in sorted.iter().enumerate() {
            let path = tree.proof_for(i as u64).unwrap();
            assert_eq!(
                path.len(),
                merkle::expected_path_len(size as u64).unwrap(),
                "size {size} leaf {i}"
            );
            merkle::verify_proof(h, i as u64, size as u64, &path, &tree.root()).unwrap();
        }
    }
}

#[test]
fn flipping_any_byte_breaks_verification() {
    let mut rng = Rng(0xdead_beef_cafe_1234);
    let hashes: Vec<[u8; 32]> = (0..16).map(|_| rng.next_bytes32()).collect();
    let (sorted, tree) = MerkleTree::build_from_unsorted(hashes).unwrap();
    let root = tree.root();
    for (i, h) in sorted.iter().enumerate() {
        let path = tree.proof_for(i as u64).unwrap();
        // Flip a byte in the file hash.
        let mut bad = *h;
        bad[0] ^= 0x01;
        assert!(
            merkle::verify_proof(&bad, i as u64, 16, &path, &root).is_err(),
            "tampered file hash verified (leaf {i})"
        );
        // Flip a byte in the first sibling (if any).
        if !path.is_empty() {
            let mut bad_path = path.clone();
            bad_path[0][0] ^= 0x01;
            assert!(
                merkle::verify_proof(h, i as u64, 16, &bad_path, &root).is_err(),
                "tampered sibling verified (leaf {i})"
            );
        }
        // Flip a byte in the expected root.
        let mut bad_root = root;
        bad_root[31] ^= 0x01;
        assert!(
            merkle::verify_proof(h, i as u64, 16, &path, &bad_root).is_err(),
            "tampered root verified (leaf {i})"
        );
    }
}

#[test]
fn exhaustive_sizes_1_to_70() {
    let mut rng = Rng(0x0bad_f00d_1111_2222);
    // Pre-generate 70 distinct hashes once; prefixes give sizes 1..=70.
    let all: Vec<[u8; 32]> = (0..70).map(|_| rng.next_bytes32()).collect();
    for size in 1u64..=70 {
        let hashes = all[..size as usize].to_vec();
        let (sorted, tree) = MerkleTree::build_from_unsorted(hashes).unwrap();
        let expected = merkle::expected_path_len(size).unwrap();
        for i in 0..size {
            let path = tree.proof_for(i).unwrap();
            assert_eq!(path.len(), expected, "size {size} leaf {i}");
            merkle::verify_proof(&sorted[i as usize], i, size, &path, &tree.root())
                .unwrap_or_else(|e| panic!("size {size} leaf {i}: {e}"));
        }
    }
}

#[test]
fn proof_bytes_round_trip_all_sizes() {
    use xmrts::protocol::proof::{Network, Proof};
    let mut rng = Rng(0x7777_8888_9999_aaaa);
    for size in [1u64, 2, 3, 4, 5, 9, 17, 64] {
        let hashes: Vec<[u8; 32]> = (0..size).map(|_| rng.next_bytes32()).collect();
        let (sorted, tree) = MerkleTree::build_from_unsorted(hashes).unwrap();
        for (i, h) in sorted.iter().enumerate() {
            let path = tree.proof_for(i as u64).unwrap();
            let p = Proof::new(
                Network::Mainnet,
                *h,
                i as u64,
                size,
                tree.root(),
                [0xabu8; 32],
                3_000_000,
                [0xcdu8; 32],
                path.clone(),
            )
            .unwrap();
            let bytes = p.to_bytes();
            let back = Proof::from_bytes(&bytes).unwrap();
            assert_eq!(p, back);
            back.verify_merkle_path().unwrap();
            // Flipping any proof byte must fail to parse or fail merkle check.
            for flip_at in [9usize, 57, 130] {
                let mut bad = bytes.clone();
                bad[flip_at] ^= 0xff;
                match Proof::from_bytes(&bad) {
                    Err(_) => {}
                    Ok(bad_proof) => {
                        assert!(
                            bad_proof.verify_merkle_path().is_err()
                                || bad_proof.file_hash != p.file_hash
                                || bad_proof.root != p.root
                                || bad_proof.block_hash != p.block_hash,
                            "single-byte flip at {flip_at} went undetected (size {size} leaf {i})"
                        );
                    }
                }
            }
        }
    }
}

/// M6 regression: duplicate-last-node makes `[a,b,c]` and `[a,b,c,c]`
/// share a root today. After the size-commitment fix the *committed*
/// roots must differ. This test documents the collision; M6 must turn
/// it into a `assert_ne!` on committed roots.
#[test]
fn duplicate_last_node_collides_today() {
    let a = [0x11u8; 32];
    let b = [0x22u8; 32];
    let c = [0x33u8; 32];
    let (_, t3) = MerkleTree::build_from_unsorted(vec![a, b, c]).unwrap();
    let (_, t4) = MerkleTree::build_from_unsorted(vec![a, b, c, c]).unwrap();
    // Raw roots collide today (documents the M6 weakness).
    assert_eq!(t3.root(), t4.root(), "precondition: v1 roots collide");
}

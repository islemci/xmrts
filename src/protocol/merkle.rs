//! Deterministic Merkle tree (spec §3, MERKLE_V1).
//!
//! ```text
//! leaf = SHA256(0x00 || file_hash)
//! node = SHA256(0x01 || left || right)
//! ```
//! Leaves are sorted by file hash (byte-lexicographic). Odd nodes are
//! handled by duplicating the last node. A single leaf tree has
//! `root = leaf`.

use crate::protocol::hash::hash_bytes;
use thiserror::Error;

/// Merkle algorithm/version identifier.
pub const MERKLE_V1: u8 = 0x01;
/// V2: same tree shape as V1 (duplicate-last-node), but the chain
/// commitment binds the tree size (M6 fix for the CVE-2012-2459 pattern
/// where `[a,b,c]` and `[a,b,c,c]` shared a root).
pub const MERKLE_V2: u8 = 0x02;

pub const DOMAIN_LEAF: u8 = 0x00;
pub const DOMAIN_NODE: u8 = 0x01;
/// Domain separator for the size commitment:
/// `commit_root = SHA256(0x02 || tree_size_le_u64 || top_root)`.
pub const DOMAIN_COMMIT: u8 = 0x02;

#[derive(Debug, Error)]
pub enum MerkleError {
    #[error("empty tree: at least one leaf is required")]
    Empty,
    #[error("unknown merkle version: {0:#04x}")]
    UnknownVersion(u8),
    #[error("leaf index {index} out of bounds for tree size {size}")]
    IndexOutOfBounds { index: u64, size: u64 },
    #[error("bad sibling count: got {got}, expected {expected} for tree size {size}")]
    BadSiblingCount {
        got: usize,
        expected: usize,
        size: u64,
    },
    #[error("merkle root mismatch")]
    RootMismatch,
}

pub fn check_version(v: u8) -> Result<(), MerkleError> {
    if v == MERKLE_V1 || v == MERKLE_V2 {
        Ok(())
    } else {
        Err(MerkleError::UnknownVersion(v))
    }
}

/// Size commitment (M6, Option A):
/// `commit_root = SHA256(0x02 || tree_size_le_u64 || top_root)`.
///
/// V2 proofs carry `top_root` in the proof body (so existing Merkle paths
/// keep working) but commit `commit_root` in `tx_extra`. Verifiers recompute
/// it from `(proof.root, proof.tree_size)` and compare against the chain.
/// Different sizes therefore commit differently even when the raw tree
/// roots collide.
pub fn commit_root(top_root: &[u8; 32], tree_size: u64) -> [u8; 32] {
    let mut buf = [0u8; 41];
    buf[0] = DOMAIN_COMMIT;
    buf[1..9].copy_from_slice(&tree_size.to_le_bytes());
    buf[9..41].copy_from_slice(top_root);
    hash_bytes(&buf)
}

/// The commitment value for a tree: V1 commits the raw root (legacy),
/// V2 commits the size-bound root.
pub fn commitment_for_version(top_root: &[u8; 32], tree_size: u64, merkle_ver: u8) -> [u8; 32] {
    if merkle_ver == MERKLE_V2 {
        commit_root(top_root, tree_size)
    } else {
        *top_root
    }
}

/// `leaf = SHA256(0x00 || file_hash)`.
pub fn leaf_from_file_hash(file_hash: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 33];
    buf[0] = DOMAIN_LEAF;
    buf[1..].copy_from_slice(file_hash);
    hash_bytes(&buf)
}

/// `node = SHA256(0x01 || left || right)`.
pub fn node_hash(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 65];
    buf[0] = DOMAIN_NODE;
    buf[1..33].copy_from_slice(left);
    buf[33..].copy_from_slice(right);
    hash_bytes(&buf)
}

/// Sort file hashes byte-lexicographically (spec §3 rule 1).
pub fn sort_hashes(mut hashes: Vec<[u8; 32]>) -> Vec<[u8; 32]> {
    hashes.sort();
    hashes
}

/// Expected sibling count for a tree size: 0 iff size == 1, else
/// `ceil(log2(size))`.
pub fn expected_path_len(tree_size: u64) -> Result<usize, MerkleError> {
    if tree_size == 0 {
        return Err(MerkleError::Empty);
    }
    if tree_size == 1 {
        return Ok(0);
    }
    // ceil(log2(n)) = 64 - leading_zeros(n-1)
    Ok((64 - (tree_size - 1).leading_zeros()) as usize)
}

/// A tree built over **already sorted** leaves.
#[derive(Debug, Clone)]
pub struct MerkleTree {
    /// levels[0] = leaves (sorted), levels[last] = single root.
    levels: Vec<Vec<[u8; 32]>>,
}

impl MerkleTree {
    /// Build from sorted file hashes (call `sort_hashes` first, or use
    /// [`build_from_unsorted`]).
    pub fn build_sorted(file_hashes: &[[u8; 32]]) -> Result<Self, MerkleError> {
        if file_hashes.is_empty() {
            return Err(MerkleError::Empty);
        }
        let mut levels: Vec<Vec<[u8; 32]>> = Vec::new();
        levels.push(file_hashes.iter().map(leaf_from_file_hash).collect());
        while levels.last().expect("nonempty").len() > 1 {
            let prev = levels.last().expect("nonempty");
            let mut next = Vec::with_capacity(prev.len().div_ceil(2));
            let mut i = 0;
            while i < prev.len() {
                let left = &prev[i];
                let right = if i + 1 < prev.len() {
                    &prev[i + 1]
                } else {
                    // Odd-node rule: duplicate the last node.
                    &prev[i]
                };
                next.push(node_hash(left, right));
                i += 2;
            }
            levels.push(next);
        }
        Ok(Self { levels })
    }

    /// Sort then build. Returns the sorted hashes alongside the tree so
    /// callers can map original inputs to leaf indexes.
    pub fn build_from_unsorted(
        file_hashes: Vec<[u8; 32]>,
    ) -> Result<(Vec<[u8; 32]>, Self), MerkleError> {
        let sorted = sort_hashes(file_hashes);
        let tree = Self::build_sorted(&sorted)?;
        Ok((sorted, tree))
    }

    pub fn tree_size(&self) -> u64 {
        self.levels[0].len() as u64
    }

    pub fn root(&self) -> [u8; 32] {
        self.levels.last().expect("built")[0]
    }

    /// Sibling hashes from leaf level up (leaf-up order).
    pub fn proof_for(&self, leaf_index: u64) -> Result<Vec<[u8; 32]>, MerkleError> {
        let size = self.tree_size();
        if leaf_index >= size {
            return Err(MerkleError::IndexOutOfBounds {
                index: leaf_index,
                size,
            });
        }
        let mut idx = leaf_index as usize;
        let mut path = Vec::new();
        for level in &self.levels[..self.levels.len() - 1] {
            let sibling = if idx.is_multiple_of(2) {
                if idx + 1 < level.len() {
                    level[idx + 1]
                } else {
                    level[idx] // duplicated odd node
                }
            } else {
                level[idx - 1]
            };
            path.push(sibling);
            idx /= 2;
        }
        Ok(path)
    }
}

/// Verify a Merkle path (spec §3 rule 6 + §8).
pub fn verify_proof(
    file_hash: &[u8; 32],
    leaf_index: u64,
    tree_size: u64,
    siblings: &[[u8; 32]],
    expected_root: &[u8; 32],
) -> Result<(), MerkleError> {
    if tree_size == 0 {
        return Err(MerkleError::Empty);
    }
    if leaf_index >= tree_size {
        return Err(MerkleError::IndexOutOfBounds {
            index: leaf_index,
            size: tree_size,
        });
    }
    let expected = expected_path_len(tree_size)?;
    if siblings.len() != expected {
        return Err(MerkleError::BadSiblingCount {
            got: siblings.len(),
            expected,
            size: tree_size,
        });
    }
    let mut cur = leaf_from_file_hash(file_hash);
    let mut idx = leaf_index;
    for sib in siblings {
        if idx.is_multiple_of(2) {
            cur = node_hash(&cur, sib);
        } else {
            cur = node_hash(sib, &cur);
        }
        idx /= 2;
    }
    if &cur == expected_root {
        Ok(())
    } else {
        Err(MerkleError::RootMismatch)
    }
}

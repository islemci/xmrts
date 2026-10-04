//! `.xmrts` proof format (spec §5): compact binary, versioned, LE integers.
//!
//! Layout (165 + 32*N bytes):
//! `XMRTS || ver || hash_algo || merkle_ver || network || file_hash ||
//!  leaf_index || tree_size || root || txid || block_height ||
//!  block_hash || path_len || siblings...`

use crate::protocol::commitment::{MAGIC, PROTOCOL_VERSION};
use crate::protocol::hash::HASH_SHA256;
use crate::protocol::merkle::{self, MERKLE_V1};
use thiserror::Error;

pub const PROOF_MIN_LEN: usize = 165;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Network {
    Mainnet = 0x00,
    Testnet = 0x01,
    Stagenet = 0x02,
}

impl Network {
    pub fn from_u8(v: u8) -> Result<Self, ProofError> {
        match v {
            0x00 => Ok(Self::Mainnet),
            0x01 => Ok(Self::Testnet),
            0x02 => Ok(Self::Stagenet),
            _ => Err(ProofError::UnknownNetwork(v)),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mainnet => "mainnet",
            Self::Testnet => "testnet",
            Self::Stagenet => "stagenet",
        }
    }

    #[allow(clippy::should_implement_trait)]
    pub fn from_str(s: &str) -> Result<Self, ProofError> {
        match s.to_ascii_lowercase().as_str() {
            "mainnet" => Ok(Self::Mainnet),
            "testnet" => Ok(Self::Testnet),
            "stagenet" => Ok(Self::Stagenet),
            _ => Err(ProofError::Malformed(format!("unknown network '{s}'"))),
        }
    }
}

#[derive(Debug, Error)]
pub enum ProofError {
    #[error("proof too short: {0} bytes")]
    TooShort(usize),
    #[error("bad magic")]
    BadMagic,
    #[error("unsupported proof version {0:#04x}")]
    UnsupportedVersion(u8),
    #[error("unknown hash algorithm {0:#04x}")]
    UnknownHashAlgo(u8),
    #[error("unknown merkle version {0:#04x}")]
    UnknownMerkleVer(u8),
    #[error("unknown network id {0:#04x}")]
    UnknownNetwork(u8),
    #[error("malformed proof: {0}")]
    Malformed(String),
    #[error(transparent)]
    Merkle(#[from] merkle::MerkleError),
}

/// A parsed `.xmrts` proof. No filename is stored (spec §5, §7).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proof {
    pub hash_algo: u8,
    pub merkle_ver: u8,
    pub network: Network,
    pub file_hash: [u8; 32],
    pub leaf_index: u64,
    pub tree_size: u64,
    pub root: [u8; 32],
    pub txid: [u8; 32],
    pub block_height: u64,
    pub block_hash: [u8; 32],
    pub siblings: Vec<[u8; 32]>,
}

impl Proof {
    /// Create an anchored proof (post-confirmation).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        network: Network,
        file_hash: [u8; 32],
        leaf_index: u64,
        tree_size: u64,
        root: [u8; 32],
        txid: [u8; 32],
        block_height: u64,
        block_hash: [u8; 32],
        siblings: Vec<[u8; 32]>,
    ) -> Result<Self, ProofError> {
        let p = Self {
            hash_algo: HASH_SHA256,
            merkle_ver: MERKLE_V1,
            network,
            file_hash,
            leaf_index,
            tree_size,
            root,
            txid,
            block_height,
            block_hash,
            siblings,
        };
        p.validate_shape()?;
        Ok(p)
    }

    /// Create a pending (pre-confirmation) proof. `verify` must treat this
    /// as unanchored and fail closed.
    pub fn new_pending(
        network: Network,
        file_hash: [u8; 32],
        leaf_index: u64,
        tree_size: u64,
        root: [u8; 32],
        siblings: Vec<[u8; 32]>,
    ) -> Result<Self, ProofError> {
        Self::new(
            network, file_hash, leaf_index, tree_size, root, [0u8; 32], 0, [0u8; 32], siblings,
        )
    }

    pub fn is_pending(&self) -> bool {
        self.block_height == 0
    }

    fn validate_shape(&self) -> Result<(), ProofError> {
        if self.tree_size == 0 {
            return Err(ProofError::Malformed("tree_size is 0".into()));
        }
        if self.leaf_index >= self.tree_size {
            return Err(ProofError::Malformed(format!(
                "leaf_index {} >= tree_size {}",
                self.leaf_index, self.tree_size
            )));
        }
        let expected = merkle::expected_path_len(self.tree_size).map_err(ProofError::Merkle)?;
        if self.siblings.len() != expected {
            return Err(ProofError::Malformed(format!(
                "sibling count {} != expected {expected} for tree_size {}",
                self.siblings.len(),
                self.tree_size
            )));
        }
        Ok(())
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(PROOF_MIN_LEN + 32 * self.siblings.len());
        out.extend_from_slice(&MAGIC);
        out.push(PROTOCOL_VERSION);
        out.push(self.hash_algo);
        out.push(self.merkle_ver);
        out.push(self.network as u8);
        out.extend_from_slice(&self.file_hash);
        out.extend_from_slice(&self.leaf_index.to_le_bytes());
        out.extend_from_slice(&self.tree_size.to_le_bytes());
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.txid);
        out.extend_from_slice(&self.block_height.to_le_bytes());
        out.extend_from_slice(&self.block_hash);
        out.extend_from_slice(&(self.siblings.len() as u32).to_le_bytes());
        for s in &self.siblings {
            out.extend_from_slice(s);
        }
        out
    }

    /// Parse untrusted input with full bounds validation (fuzz target).
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ProofError> {
        if bytes.len() < PROOF_MIN_LEN {
            return Err(ProofError::TooShort(bytes.len()));
        }
        if bytes[0..5] != MAGIC {
            return Err(ProofError::BadMagic);
        }
        let version = bytes[5];
        if version != PROTOCOL_VERSION {
            return Err(ProofError::UnsupportedVersion(version));
        }
        let (hash_algo, merkle_ver, network_id) = (bytes[6], bytes[7], bytes[8]);
        if hash_algo != HASH_SHA256 {
            return Err(ProofError::UnknownHashAlgo(hash_algo));
        }
        if merkle_ver != MERKLE_V1 {
            return Err(ProofError::UnknownMerkleVer(merkle_ver));
        }
        let network = Network::from_u8(network_id)?;
        let mut file_hash = [0u8; 32];
        file_hash.copy_from_slice(&bytes[9..41]);
        let leaf_index = u64::from_le_bytes(bytes[41..49].try_into().expect("len"));
        let tree_size = u64::from_le_bytes(bytes[49..57].try_into().expect("len"));
        if tree_size == 0 || tree_size > 1_000_000_000 {
            return Err(ProofError::Malformed(format!("bad tree_size {tree_size}")));
        }
        if leaf_index >= tree_size {
            return Err(ProofError::Malformed(format!(
                "leaf_index {leaf_index} >= tree_size {tree_size}"
            )));
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes[57..89]);
        let mut txid = [0u8; 32];
        txid.copy_from_slice(&bytes[89..121]);
        let block_height = u64::from_le_bytes(bytes[121..129].try_into().expect("len"));
        let mut block_hash = [0u8; 32];
        block_hash.copy_from_slice(&bytes[129..161]);
        let path_len = u32::from_le_bytes(bytes[161..165].try_into().expect("len")) as usize;
        let expected = merkle::expected_path_len(tree_size).map_err(ProofError::Merkle)?;
        if path_len != expected {
            return Err(ProofError::Malformed(format!(
                "path_len {path_len} != expected {expected} for tree_size {tree_size}"
            )));
        }
        if path_len > 64 {
            return Err(ProofError::Malformed(format!(
                "path_len {path_len} too large"
            )));
        }
        if bytes.len() != PROOF_MIN_LEN + 32 * path_len {
            return Err(ProofError::Malformed(format!(
                "trailing bytes: len {} != expected {}",
                bytes.len(),
                PROOF_MIN_LEN + 32 * path_len
            )));
        }
        let mut siblings = Vec::with_capacity(path_len);
        for i in 0..path_len {
            let off = 165 + 32 * i;
            let mut s = [0u8; 32];
            s.copy_from_slice(&bytes[off..off + 32]);
            siblings.push(s);
        }
        Ok(Self {
            hash_algo,
            merkle_ver,
            network,
            file_hash,
            leaf_index,
            tree_size,
            root,
            txid,
            block_height,
            block_hash,
            siblings,
        })
    }

    /// Verify the cryptographic path (file hash already checked by caller):
    /// recompute the root and compare.
    pub fn verify_merkle_path(&self) -> Result<(), ProofError> {
        merkle::verify_proof(
            &self.file_hash,
            self.leaf_index,
            self.tree_size,
            &self.siblings,
            &self.root,
        )
        .map_err(ProofError::Merkle)?;
        Ok(())
    }

    /// Human-readable dump (`verify --verbose`).
    pub fn describe(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("version:      {}\n", PROTOCOL_VERSION));
        s.push_str(&format!(
            "hash_algo:     SHA-256 (0x{:02x})\n",
            self.hash_algo
        ));
        s.push_str(&format!("merkle_ver:    v1 (0x{:02x})\n", self.merkle_ver));
        s.push_str(&format!("network:       {}\n", self.network.as_str()));
        s.push_str(&format!("file_hash:     {}\n", hex::encode(self.file_hash)));
        s.push_str(&format!("leaf_index:    {}\n", self.leaf_index));
        s.push_str(&format!("tree_size:     {}\n", self.tree_size));
        s.push_str(&format!("root:          {}\n", hex::encode(self.root)));
        s.push_str(&format!("txid:          {}\n", hex::encode(self.txid)));
        s.push_str(&format!("block_height:  {}\n", self.block_height));
        s.push_str(&format!(
            "block_hash:    {}\n",
            hex::encode(self.block_hash)
        ));
        s.push_str(&format!("siblings:      {} hashes\n", self.siblings.len()));
        for (i, sib) in self.siblings.iter().enumerate() {
            s.push_str(&format!("  [{i}] {}\n", hex::encode(sib)));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_single_leaf() {
        let p = Proof::new(
            Network::Mainnet,
            [0x01u8; 32],
            0,
            1,
            [0x02u8; 32],
            [0x03u8; 32],
            1234567,
            [0x04u8; 32],
            vec![],
        )
        .unwrap();
        let b = p.to_bytes();
        assert_eq!(b.len(), PROOF_MIN_LEN);
        assert_eq!(Proof::from_bytes(&b).unwrap(), p);
    }

    #[test]
    fn rejects_trailing_bytes_and_bad_magic() {
        let p = Proof::new(
            Network::Testnet,
            [0u8; 32],
            0,
            1,
            [0u8; 32],
            [0u8; 32],
            1,
            [0u8; 32],
            vec![],
        )
        .unwrap();
        let mut b = p.to_bytes();
        b.push(0xFF);
        assert!(Proof::from_bytes(&b).is_err());
        b.pop();
        b[0] = 0x00;
        assert!(matches!(Proof::from_bytes(&b), Err(ProofError::BadMagic)));
    }

    #[test]
    fn rejects_path_len_mismatch() {
        // tree_size 3 requires 2 siblings; tamper the count.
        let mut p = Proof::new(
            Network::Mainnet,
            [0u8; 32],
            0,
            3,
            [0u8; 32],
            [0u8; 32],
            1,
            [0u8; 32],
            vec![[0u8; 32], [0u8; 32]],
        )
        .unwrap()
        .to_bytes();
        p[161] = 1; // path_len 2 -> 1
        assert!(Proof::from_bytes(&p).is_err());
    }
}

//! Streaming file hashing (spec §2). SHA-256, algorithm id 0x01.

use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;
use thiserror::Error;

/// Hash algorithm identifier for SHA-256.
pub const HASH_SHA256: u8 = 0x01;

#[derive(Debug, Error)]
pub enum HashError {
    #[error("unknown hash algorithm id: {0:#04x}")]
    UnknownAlgorithm(u8),
    #[error("I/O error hashing file: {0}")]
    Io(#[from] io::Error),
}

pub fn check_algorithm(id: u8) -> Result<(), HashError> {
    if id == HASH_SHA256 {
        Ok(())
    } else {
        Err(HashError::UnknownAlgorithm(id))
    }
}

/// SHA-256 of in-memory bytes (used for leaves/nodes and tests).
pub fn hash_bytes(data: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(data);
    h.finalize().into()
}

/// Streaming SHA-256 of a file. Never loads the whole file into RAM.
pub fn hash_file(path: &Path) -> Result<[u8; 32], HashError> {
    let file = File::open(path)?;
    hash_reader(file)
}

/// Streaming file hash with a per-chunk progress callback (bytes read).
/// [`hash_file`] delegates here with a no-op callback.
pub fn hash_file_with_progress(
    path: &Path,
    mut on_chunk: impl FnMut(u64),
) -> Result<[u8; 32], HashError> {
    let file = File::open(path)?;
    let mut h = Sha256::new();
    let mut reader = io::BufReader::new(file);
    let mut buf = [0u8; 65536];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
        on_chunk(n as u64);
    }
    Ok(h.finalize().into())
}

pub fn hash_reader<R: Read>(mut reader: R) -> Result<[u8; 32], HashError> {
    let mut h = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = reader.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_hash_matches_spec() {
        let h = hash_bytes(b"");
        assert_eq!(
            hex::encode(h),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn abc_vector() {
        let h = hash_bytes(b"abc");
        assert_eq!(
            hex::encode(h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn rejects_unknown_algorithm() {
        assert!(check_algorithm(0x01).is_ok());
        assert!(check_algorithm(0xFF).is_err());
    }
}

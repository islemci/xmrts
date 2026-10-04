//! Golden-vector tests: `tests/vectors/v1.json` is normative (spec §10).
//! If these fail, the protocol changed — bump the version, don't edit vectors.

use xmrts::protocol::{commitment, hash, merkle::MerkleTree};

fn hex32(s: &str) -> [u8; 32] {
    hex::decode(s).unwrap().try_into().unwrap()
}

#[test]
fn file_hash_vectors() {
    assert_eq!(
        hex::encode(hash::hash_bytes(b"")),
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
    );
    assert_eq!(
        hex::encode(hash::hash_bytes(b"abc")),
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
    assert_eq!(
        hex::encode(hash::hash_bytes(b"hello xmrts")),
        "99b3ec575ec5aedf2b205bcd83cc05b5d092e5a781c0e1abdb7067d8b673aef6"
    );
}

#[test]
fn one_leaf_root_is_leaf() {
    let h = hex32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    let tree = MerkleTree::build_sorted(&[h]).unwrap();
    assert_eq!(
        hex::encode(tree.root()),
        "4e59bf27372b1304bc0b137d1be9d566ad58b154b6a6b5778af7f414b1d4b84c"
    );
    assert!(tree.proof_for(0).unwrap().is_empty());
}

#[test]
fn two_leaf_vector() {
    let a = hex32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    let b = hex32("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
    // Unsorted input must still give the sorted root (invocation-order independence).
    let (_, t1) = MerkleTree::build_from_unsorted(vec![b, a]).unwrap();
    let (_, t2) = MerkleTree::build_from_unsorted(vec![a, b]).unwrap();
    assert_eq!(t1.root(), t2.root());
    assert_eq!(
        hex::encode(t1.root()),
        "fb12d6ae208106a73219c7c61bcebf429a6d9ae5c1dc35159a205814458234c5"
    );
}

#[test]
fn three_leaf_odd_duplication_vector() {
    let hs = [
        "99b3ec575ec5aedf2b205bcd83cc05b5d092e5a781c0e1abdb7067d8b673aef6",
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    ]
    .map(hex32);
    let tree = MerkleTree::build_sorted(&hs).unwrap();
    assert_eq!(
        hex::encode(tree.root()),
        "6a1586e9c1be9e05ec67443d4a8eff58435c5aca55debd1535b3cb391f988d5c"
    );
    // Every leaf verifies against the root.
    for i in 0..3 {
        let path = tree.proof_for(i).unwrap();
        assert_eq!(path.len(), 2);
        xmrts::protocol::merkle::verify_proof(&hs[i as usize], i, 3, &path, &tree.root()).unwrap();
    }
}

#[test]
fn commitment_vector() {
    let root = hex32("fb12d6ae208106a73219c7c61bcebf429a6d9ae5c1dc35159a205814458234c5");
    assert_eq!(
        commitment::build_tx_extra_hex(&root),
        "0228584d525453010101fb12d6ae208106a73219c7c61bcebf429a6d9ae5c1dc35159a205814458234c5"
    );
}

#[test]
fn duplicate_hashes_get_distinct_leaves() {
    let h = hex32("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    let (_, tree) = MerkleTree::build_from_unsorted(vec![h, h]).unwrap();
    assert_eq!(tree.tree_size(), 2);
    for i in 0..2 {
        let path = tree.proof_for(i).unwrap();
        xmrts::protocol::merkle::verify_proof(&h, i, 2, &path, &tree.root()).unwrap();
    }
}

#[test]
fn proof_parser_rejects_garbage() {
    use xmrts::protocol::proof::Proof;
    assert!(Proof::from_bytes(&[]).is_err());
    assert!(Proof::from_bytes(&[0u8; 200]).is_err());
    assert!(Proof::from_bytes(&[0xFFu8; 165]).is_err());
}

//! Offline CLI integration: stamp --offline then verify --offline.
//! No wallet or daemon required.

use std::process::Command;

fn bin() -> std::path::PathBuf {
    let mut p = std::path::PathBuf::from(env!("CARGO_BIN_EXE_xmrts"));
    let _ = &mut p;
    p
}

#[test]
fn offline_stamp_and_verify_round_trip() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.txt");
    let b = dir.path().join("b.txt");
    let c = dir.path().join("c.txt");
    std::fs::write(&a, b"alpha").unwrap();
    std::fs::write(&b, b"beta").unwrap();
    std::fs::write(&c, b"gamma").unwrap();
    let out = dir.path().join("proofs");

    let status = Command::new(bin())
        .args([
            "stamp",
            a.to_str().unwrap(),
            b.to_str().unwrap(),
            c.to_str().unwrap(),
            "--offline",
            "--out-dir",
            out.to_str().unwrap(),
        ])
        .status()
        .unwrap();
    assert!(status.success());

    for name in ["a.txt.xmrts", "b.txt.xmrts", "c.txt.xmrts"] {
        assert!(out.join(name).exists(), "missing {name}");
    }

    // Verify each file against its proof (crypto-only).
    for (file, proof) in [
        (&a, "a.txt.xmrts"),
        (&b, "b.txt.xmrts"),
        (&c, "c.txt.xmrts"),
    ] {
        let status = Command::new(bin())
            .args([
                "verify",
                file.to_str().unwrap(),
                out.join(proof).to_str().unwrap(),
                "--offline",
            ])
            .status()
            .unwrap();
        assert!(status.success());
    }

    // Tampered file must fail.
    let evil = dir.path().join("evil.txt");
    std::fs::write(&evil, b"alpha!").unwrap();
    let status = Command::new(bin())
        .args([
            "verify",
            evil.to_str().unwrap(),
            out.join("a.txt.xmrts").to_str().unwrap(),
            "--offline",
        ])
        .status()
        .unwrap();
    assert!(!status.success());
}

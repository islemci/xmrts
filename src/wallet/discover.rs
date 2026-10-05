//! Wallet auto discovery across known folders on all OS.
//!
//! Scans the places Monero apps keep wallets. Short human output.
//! No passwords. No seeds. Only folder paths and wallet names.

use std::path::{Path, PathBuf};

/// One folder that holds wallets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FoundDir {
    pub dir: PathBuf,
    pub wallets: Vec<String>,
}

/// Known wallet folders in check order. Only existing dirs are kept.
/// Covers Monero GUI and CLI defaults plus Feather guesses on all OS.
pub fn candidate_wallet_dirs() -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    let mut push = |p: PathBuf| {
        if !out.contains(&p) {
            out.push(p);
        }
    };

    if let Some(user) = directories::UserDirs::new() {
        let home = user.home_dir();
        push(home.join("Monero").join("wallets"));
        push(home.join("monero").join("wallets"));
        push(home.join("Monero"));
        push(home.join("monero"));
        if let Some(docs) = user.document_dir() {
            push(docs.join("Monero").join("wallets"));
            push(docs.join("monero").join("wallets"));
            push(docs.join("Monero"));
            push(docs.join("Feather"));
            push(docs.join("feather"));
        }
        push(home.join("Documents").join("Monero").join("wallets"));
        push(home.join("Documents").join("monero").join("wallets"));
        push(home.join("Feather"));
        push(home.join("feather"));
    }
    if let Some(base) = directories::BaseDirs::new() {
        push(base.data_dir().join("monero").join("wallets"));
        push(base.data_dir().join("Monero").join("wallets"));
        push(base.config_dir().join("feather").join("wallets"));
        push(base.config_dir().join("Feather").join("wallets"));
    }
    #[cfg(windows)]
    {
        if let Ok(profile) = std::env::var("USERPROFILE") {
            let p = PathBuf::from(profile);
            push(p.join("Documents").join("Monero").join("wallets"));
            push(p.join("Monero").join("wallets"));
        }
    }

    out.into_iter().filter(|p| p.is_dir()).collect()
}

/// Wallet names in one folder. Looks at top level plus one level down.
/// Strips the `.keys` suffix. Returns paths relative to `dir`.
pub fn scan_dir(dir: &Path) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    let Ok(top) = std::fs::read_dir(dir) else {
        return out;
    };
    for entry in top.flatten() {
        let path = entry.path();
        if path.is_file() && path.extension().is_some_and(|e| e == "keys") {
            if let Some(name) = relative_wallet_name(dir, &path) {
                out.push(name);
            }
        } else if path.is_dir() {
            if let Ok(sub) = std::fs::read_dir(&path) {
                for entry in sub.flatten() {
                    let p = entry.path();
                    if p.is_file() && p.extension().is_some_and(|e| e == "keys") {
                        if let Some(name) = relative_wallet_name(dir, &p) {
                            out.push(name);
                        }
                    }
                }
            }
        }
    }
    out.sort();
    out.dedup();
    out
}

fn relative_wallet_name(base: &Path, keys_path: &Path) -> Option<String> {
    let rel = keys_path.strip_prefix(base).ok()?;
    let s = rel.to_string_lossy().into_owned();
    s.strip_suffix(".keys").map(String::from)
}

/// Scan all known folders. Returns only folders that hold wallets.
pub fn discover() -> Vec<FoundDir> {
    let mut out = Vec::new();
    for dir in candidate_wallet_dirs() {
        let wallets = scan_dir(&dir);
        if !wallets.is_empty() {
            out.push(FoundDir { dir, wallets });
        }
    }
    out
}

/// Same as [`discover`] but also checks one explicit folder first.
/// Used when the user passed `--wallet-dir` or has one saved.
pub fn discover_with_extra(extra: Option<&str>) -> Vec<FoundDir> {
    let mut out = Vec::new();
    if let Some(e) = extra {
        let p = PathBuf::from(e);
        if p.is_dir() {
            let wallets = scan_dir(&p);
            if !wallets.is_empty() {
                out.push(FoundDir { dir: p, wallets });
            }
        }
    }
    for found in discover() {
        if !out.iter().any(|f: &FoundDir| f.dir == found.dir) {
            out.push(found);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn finds_top_level_and_nested_keys() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("a.keys"), b"x").unwrap();
        std::fs::write(dir.path().join("notes.txt"), b"x").unwrap();
        let sub = dir.path().join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("b.keys"), b"x").unwrap();
        let got = scan_dir(dir.path());
        assert!(got.contains(&"a".to_string()));
        assert!(got.iter().any(|n| n.ends_with('b')));
        assert!(!got.iter().any(|n| n.contains("notes")));
    }

    #[test]
    fn strips_keys_suffix_relative() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("mine.keys"), b"x").unwrap();
        let got = scan_dir(dir.path());
        assert_eq!(got, vec!["mine".to_string()]);
    }

    #[test]
    fn candidates_do_not_panic_and_dedupe() {
        let dirs = candidate_wallet_dirs();
        let mut seen = std::collections::HashSet::new();
        for d in dirs {
            assert!(d.is_dir());
            assert!(seen.insert(d));
        }
    }
}

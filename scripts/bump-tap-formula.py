#!/usr/bin/env python3
"""Regenerate the Homebrew tap formula for xmrts from release metadata.

Usage:
  bump-tap-formula.py --formula Formula/xmrts.rb --owner OWNER --repo xmrts \\
      --version 0.1.0 --tarball xmrts-macos-arm64=<sha256> \\
      --tarball xmrts-linux-x86_64=<sha256> [...]

The formula is fully regenerated (never sed-patched), so output is
deterministic for a given input. Unknown archive names fail loudly
instead of being silently skipped.
"""
import argparse
import sys

DESC = "Self-sovereign file timestamping on Monero"

# archive name -> (os block, arch block)
PLATFORMS = {
    "xmrts-macos-arm64": ("macos", "arm"),
    "xmrts-macos-x86_64": ("macos", "intel"),
    "xmrts-linux-x86_64": ("linux", "intel"),
    "xmrts-linux-arm64": ("linux", "arm"),
}


def parse_tarball(spec: str) -> tuple[str, str]:
    name, _, sha = spec.partition("=")
    if not name or not sha:
        raise ValueError(f"bad --tarball {spec!r}, want NAME=SHA256")
    if len(sha) != 64 or any(c not in "0123456789abcdef" for c in sha.lower()):
        raise ValueError(f"bad sha256 in {spec!r}")
    return name, sha.lower()


def render(owner: str, repo: str, version: str, tarballs: dict[str, str]) -> str:
    unknown = sorted(set(tarballs) - set(PLATFORMS))
    if unknown:
        raise ValueError(f"unknown archives (add them to PLATFORMS): {unknown}")
    by_os: dict[str, list[tuple[str, str]]] = {}
    for archive, sha in sorted(tarballs.items()):
        os_block, _ = PLATFORMS[archive]
        by_os.setdefault(os_block, []).append((archive, sha))
    lines = [
        "class Xmrts < Formula",
        f'  desc "{DESC}"',
        f'  homepage "https://github.com/{owner}/{repo}"',
        f'  version "{version}"',
        "",
    ]
    for os_block in ("macos", "linux"):
        entries = by_os.get(os_block, [])
        if not entries:
            continue
        lines.append(f"  on_{os_block} do")
        for archive, sha in entries:
            _, arch_block = PLATFORMS[archive]
            url = f"https://github.com/{owner}/{repo}/releases/download/v{version}/{archive}.tar.gz"
            lines.append(f"    on_{arch_block} do")
            lines.append(f'      url "{url}"')
            lines.append(f'      sha256 "{sha}"')
            lines.append("    end")
        lines.append("  end")
        lines.append("")
    lines += [
        "  def install",
        '    bin.install "xmrts", "monero-wallet-rpc"',
        "  end",
        "",
        "  test do",
        '    assert_match "xmrts #{version}", shell_output("#{bin}/xmrts --version")',
        "  end",
        "end",
        "",
    ]
    return "\n".join(lines)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--formula", required=True)
    ap.add_argument("--owner", required=True)
    ap.add_argument("--repo", default="xmrts")
    ap.add_argument("--version", required=True)
    ap.add_argument("--tarball", action="append", default=[])
    args = ap.parse_args()
    try:
        tarballs = dict(parse_tarball(s) for s in args.tarball)
        if not tarballs:
            raise ValueError("no --tarball given")
        text = render(args.owner, args.repo, args.version, tarballs)
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 1
    with open(args.formula, "w") as f:
        f.write(text)
    print(f"wrote {args.formula} ({len(tarballs)} platform(s))")
    return 0


if __name__ == "__main__":
    sys.exit(main())

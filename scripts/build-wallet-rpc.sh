#!/usr/bin/env bash
# Build a (patched) monero-wallet-rpc for xmrts releases.
#
# Usage:
#   MODE=static ./scripts/build-wallet-rpc.sh [monero-tag] [patch] [workdir]
#
# - Fetches the pinned Monero tag into <workdir> (reused across runs).
# - Applies the xmrts `extra`-forwarding patch (fails closed if it
#   doesn't apply cleanly — never build an unpatched wallet by accident).
# - MODE=static (default, for releases): depends-based static build,
#   portable across machines. Slow (up to hours first time).
# - MODE=dynamic (local dev only): system libs via brew/apt. Fast but the
#   binary runs only where those libs exist.
#
# Output: <workdir>/build/release/bin/monero-wallet-rpc
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
TAG="${1:-v0.18.5.0}"
PATCH="${2:-$SCRIPT_DIR/../patches/monero-wallet-rpc-extra-v0.18.5.0.patch}"
WORK="${3:-$(pwd)/../monero-release-build}"
MODE="${MODE:-static}"
# Resolve PATCH absolutely now: later `git -C` calls would otherwise
# resolve a relative path against the work tree instead of here.
case "$PATCH" in
  /*) ;;
  *) PATCH="$(pwd)/$PATCH" ;;
esac
[ -f "$PATCH" ] || { echo "patch not found: $PATCH" >&2; exit 1; }

OS="$(uname -s)"
ARCH="$(uname -m)"
case "$OS-$ARCH" in
  Darwin-arm64)  TRIPLE="aarch64-apple-darwin" ;;
  Darwin-x86_64) TRIPLE="x86_64-apple-darwin" ;;
  Linux-x86_64)  TRIPLE="x86_64-linux-gnu" ;;
  Linux-aarch64) TRIPLE="aarch64-linux-gnu" ;;
  *) echo "unsupported platform $OS-$ARCH" >&2; exit 1 ;;
esac

if [ ! -d "$WORK/.git" ]; then
  git clone --recursive --depth 1 --branch "$TAG" \
    https://github.com/monero-project/monero.git "$WORK"
else
  git -C "$WORK" fetch --depth 1 origin "refs/tags/$TAG:refs/tags/$TAG" || true
  git -C "$WORK" checkout --detach "$TAG"
fi
git -C "$WORK" submodule update --init --force

# On macOS the depends tree targets an old deployment version; without
# an explicit SDK the modern linker cannot find system libraries.
if [ "$(uname -s)" = "Darwin" ]; then
  export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"
fi

# The patch must apply to a pristine tree: stash nothing, apply verbosely.
# Idempotent: skip when already applied (re-runs), fail closed otherwise
# (never build an unpatched wallet by accident).
if git -C "$WORK" apply --check --reverse "$PATCH" 2>/dev/null; then
  echo "patch already applied, skipping"
else
  if ! git -C "$WORK" diff --quiet; then
    echo "work tree $WORK is dirty with unknown changes; refusing to build" >&2
    exit 1
  fi
  git -C "$WORK" apply --check "$PATCH"
  git -C "$WORK" apply "$PATCH"
fi
git -C "$WORK" diff --stat

if [ "$MODE" = "static" ]; then
  NPROC="$(nproc 2>/dev/null || sysctl -n hw.ncpu)"
  TOOLCHAIN="$WORK/contrib/depends/$TRIPLE/share/toolchain.cmake"
  if [ -f "$TOOLCHAIN" ]; then
    echo "depends prefix cached, skipping rebuild"
  else
    make -C "$WORK/contrib/depends" -j"$NPROC" "HOST=$TRIPLE"
  fi
  cmake -S "$WORK" -B "$WORK/build/release" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_GUI_DEPS=0 \
    -DUSE_CCACHE=1 \
    "-DCMAKE_TOOLCHAIN_FILE=$TOOLCHAIN"
else
  cmake -S "$WORK" -B "$WORK/build/release" \
    -DCMAKE_BUILD_TYPE=Release \
    -DBUILD_GUI_DEPS=0 \
    -DUSE_CCACHE=1
fi

NPROC="$(nproc 2>/dev/null || sysctl -n hw.ncpu)"
# 8 GB-class machines OOM on full parallelism for the heaviest TUs.
if [ "$NPROC" -gt 6 ]; then NPROC=6; fi
cmake --build "$WORK/build/release" --target wallet_rpc_server -j"$NPROC"

BIN="$WORK/build/release/bin/monero-wallet-rpc"
"$BIN" --version
ls -la "$BIN"

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

# Boost: 1.69 (pinned by this Monero tag) predates current
# toolchains — its build passes the dead GCC-only flag
# -fcoalesce-templates (hard error on modern Clang, 116 dead targets)
# and its locale/thread sources fail on GCC 11. Bump to 1.84.0 within
# the same packaging scheme (classic boost_X_Y_Z layout, identical .mk
# mechanics). Boost >= 1.84 requires C++14+, so raise depends cxxflags
# to the C++17 Monero itself builds with. Override via env to test
# other versions. (perl, not sed -i: portable across GNU/BSD.)
BOOST_VERSION="${BOOST_VERSION:-1.84.0}"
# Official hash per https://www.boost.org/users/history/version_1_84_0.html
BOOST_SHA256="${BOOST_SHA256:-a5800f405508f5df8114558ca9855d2640a2de8f0445f051fa1c7c3383045724}"
BOOST_MK="$WORK/contrib/depends/packages/boost.mk"
perl -pi -e 's/^\$\(package\)_version=.*$/\$(package)_version='"$BOOST_VERSION"'/' "$BOOST_MK"
perl -pi -e 's/^\$\(package\)_sha256_hash=.*$/\$(package)_sha256_hash='"$BOOST_SHA256"'/' "$BOOST_MK"
perl -pi -e 's/^\$\(package\)_cxxflags=-std=c\+\+11$/\$(package)_cxxflags=-std=c++17/' "$BOOST_MK"
grep -E "\(package\)_(version|sha256_hash)=|\(package\)_cxxflags=-std" "$BOOST_MK"

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

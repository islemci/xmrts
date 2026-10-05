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
# Cross builds (e.g. macOS-from-Linux, the way upstream builds darwin
# targets because the native-mac depends path is broken by design):
# set MONERO_HOST explicitly, autodetect otherwise.
if [ -n "${MONERO_HOST:-}" ]; then
  TRIPLE="$MONERO_HOST"
else
  case "$OS-$ARCH" in
    Darwin-arm64)  TRIPLE="aarch64-apple-darwin" ;;
    Darwin-x86_64) TRIPLE="x86_64-apple-darwin" ;;
    Linux-x86_64)  TRIPLE="x86_64-linux-gnu" ;;
    Linux-aarch64) TRIPLE="aarch64-linux-gnu" ;;
    *) echo "unsupported platform $OS-$ARCH (or set MONERO_HOST)" >&2; exit 1 ;;
  esac
fi

if [ ! -d "$WORK/.git" ]; then
  if [ -d "$WORK" ]; then
    # Cache skeleton from a previous run (restored cache dirs, no .git):
    # set it aside, clone fresh, merge it back. The cached depends prefix
    # stays valid: same tag (script pins it) and same script (cache key
    # includes this file's hash, so a changed script starts uncached).
    STASH="$(mktemp -d)"
    mv "$WORK" "$STASH/prev"
    mkdir -p "$(dirname "$WORK")"
  fi
  git clone --recursive --depth 1 --branch "$TAG" \
    https://github.com/monero-project/monero.git "$WORK"
  if [ -n "${STASH:-}" ]; then
    cp -a "$STASH/prev/." "$WORK/"
    rm -rf "$STASH"
  fi
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
# The 1.69-era b2 patches predate fixes absorbed into modern Boost.Build
# (upstream dropped them when moving past 1.69): they neither apply to
# nor are needed on 1.84+, so empty the list and neutralize the
# hardcoded invocations. Verified against upstream's own removal.
perl -pi -e 's/^\$\(package\)_patches=.*$/\$(package)_patches=/' "$BOOST_MK"
# NB: the replacement keeps the trailing `&&\` continuations: without
# them the three lines stop forming one logical recipe line and make
# dies with "missing separator" at funcs.mk eval time.
perl -0777 -pi -e 's/^  patch -p1 < .*fix_ar(options|m_arch)\.patch &&\\\n/  true \&\&\\\n/gm' "$BOOST_MK"
# Boost.Locale is dead weight with a broken build: upstream removed it as
# a required dependency on all non-Windows platforms (the only two call
# sites in 0.18.5 are already #ifdef WIN32-guarded; POSIX handles UTF-8
# natively). Mirror that: drop locale from the b2 build list and from
# CMake's required components. No source changes, no behavior change.
# (Windows/mingw32 would need it re-added, exactly as upstream does.)
perl -pi -e 's/^(\$\(package\)_config_libraries=.*regex,serialization),locale$/$1/' "$BOOST_MK"
perl -pi -e 's/^(  set\(BOOST_COMPONENTS [^)]*) locale\)$/$1)/' "$WORK/CMakeLists.txt"
grep -E "\(package\)_config_libraries=|set\(BOOST_COMPONENTS" "$BOOST_MK" "$WORK/CMakeLists.txt"
grep -E "\(package\)_(version|sha256_hash|patches)=|\(package\)_cxxflags=-std" "$BOOST_MK"

# ZeroMQ: 4.3.4 trips -Werror on sprintf deprecation under the Xcode
# 15.4+ SDK; 4.3.5 is the upstream fix (same layout/scheme, and the
# version current master pins). Asset lives under
# github.com/zeromq/libzmq/releases/download/v<VERSION>/.
export ZMQ_VERSION="4.3.5"
export ZMQ_SHA256="6653ef5910f17954861fe72332e68b03ca6e4d9c7160eb3a8de5a5a913bfab43"
ZMQ_MK="$WORK/contrib/depends/packages/zeromq.mk"
perl -pi -e 's/^(\$\(package\)_version=).*$/\1$ENV{ZMQ_VERSION}/' "$ZMQ_MK"
perl -pi -e 's/^(\$\(package\)_sha256_hash=).*$/\1$ENV{ZMQ_SHA256}/' "$ZMQ_MK"
grep -E "\(package\)_(version|sha256_hash)=" "$ZMQ_MK"
# The 0.18.5 zeromq backport (clock.cpp unused-variable, 2021) is already
# upstream in 4.3.5, so its slot gets our own one-liner instead:
# proxy.cpp `{0}` trips -Werror=missing-braces on modern Clang, `{}` is
# the upstream-blessed spelling. Same filename => zero .mk edits.
cp "$SCRIPT_DIR/../patches/zeromq-4.3.5-missing-braces.patch" \
  "$WORK/contrib/depends/patches/zeromq/06aba27b04c5822cb88a69677382a0f053367143.patch"

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
# Parallelism: roughly one heavy TU per 2 GB RAM, capped by cores.
# (8 GB laptop -> 4-6 jobs as before; 32 GB CI runner -> full cores.)
if command -v free >/dev/null 2>&1; then
  MEMGB="$(awk '/MemTotal/ {print int($2/1024/1024)}' /proc/meminfo)"
else
  MEMGB="$(sysctl -n hw.memsize 2>/dev/null | awk '{print int($1/1024/1024/1024)}')"
fi
MEMGB="${MEMGB:-8}"
JOBS="${JOBS:-$NPROC}"
[ "$JOBS" -gt "$((MEMGB / 2))" ] && JOBS="$((MEMGB / 2))"
[ "$JOBS" -lt 2 ] && JOBS=2
cmake --build "$WORK/build/release" --target wallet_rpc_server -j"$JOBS"

BIN="$WORK/build/release/bin/monero-wallet-rpc"
"$BIN" --version
ls -la "$BIN"

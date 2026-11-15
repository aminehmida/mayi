#!/bin/sh
# Builds the requester CLI as static Linux binaries, from any host.
# The result has no dependencies: copy it to the machine and run it.
#   scripts/build-linux.sh            both architectures
#   scripts/build-linux.sh aarch64    one of: x86_64, aarch64
set -eu
cd "$(dirname "$0")/.."

if command -v cargo >/dev/null 2>&1; then
    run=""
else
    run="mise exec --"
fi

for arch in ${1:-x86_64 aarch64}; do
    target="$arch-unknown-linux-musl"
    $run rustup target add "$target" >/dev/null 2>&1 || true
    # rust-lld ships with the toolchain, so no cross C toolchain is needed.
    linker_var="CARGO_TARGET_$(echo "$target" | tr 'a-z-' 'A-Z_')_LINKER"
    env "$linker_var=rust-lld" $run cargo build --release -p mayi-cli --target "$target"
    echo "Built target/$target/release/mayi"
done

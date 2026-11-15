#!/bin/sh
# Builds the Rust core for Android and for this machine (the JVM tests load
# the host build), and generates the Kotlin bindings.
#   ./build-core.sh           then ./gradlew assembleDebug
#   ./build-core.sh test      also runs the JVM tests
set -eu
cd "$(dirname "$0")"
root=../..

if command -v cargo >/dev/null 2>&1; then run=""; else run="mise exec --"; fi
sdk="${ANDROID_HOME:-/opt/homebrew/share/android-commandlinetools}"
export ANDROID_HOME="$sdk"
if [ -z "${ANDROID_NDK_HOME:-}" ]; then
    ANDROID_NDK_HOME="$sdk/ndk/$(ls "$sdk/ndk" | sort -V | tail -1)"
    export ANDROID_NDK_HOME
fi
manifest="--manifest-path $root/Cargo.toml"

$run cargo ndk $manifest -t arm64-v8a -t x86_64 -o "$PWD/app/src/main/jniLibs" build --release -p mayi-ffi
$run cargo build $manifest --release -p mayi-ffi -p mayi-cli
$run cargo run $manifest -q -p mayi-ffi --features bindgen --bin uniffi-bindgen -- \
    generate --library "$root/target/release/libmayi_ffi.dylib" --language kotlin --no-format \
    --out-dir "$PWD/app/src/main/java"

if [ "${1:-}" = "test" ]; then
    $run ./gradlew --quiet testDebugUnitTest
fi

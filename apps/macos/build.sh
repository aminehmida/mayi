#!/bin/sh
# Builds the Rust core, generates the Swift bindings, and assembles Mayi.app.
#   ./build.sh          build build/Mayi.app
#   ./build.sh test     build, then run the Swift tests
set -eu
cd "$(dirname "$0")"
root=../..
# Match the deployment target in Package.swift.
export MACOSX_DEPLOYMENT_TARGET=14.0

if command -v cargo >/dev/null 2>&1; then
    cargo="cargo"
else
    cargo="mise exec -- cargo"
fi
manifest="--manifest-path $root/Cargo.toml"

$cargo build $manifest --release -p mayi-ffi -p mayi-cli
generated=$(mktemp -d)
trap 'rm -rf "$generated"' EXIT
$cargo run $manifest -q -p mayi-ffi --features bindgen --bin uniffi-bindgen -- \
    generate --library "$root/target/release/libmayi_ffi.a" --language swift --out-dir "$generated"
mkdir -p Sources/mayi_ffiFFI/include Sources/MayiKit/Generated
cp "$generated/mayi_ffiFFI.h" Sources/mayi_ffiFFI/include/
cp "$generated/mayi_ffi.swift" Sources/MayiKit/Generated/

if [ "${1:-}" = "test" ]; then
    # With only the Command Line Tools installed (no Xcode), SwiftPM does not
    # find the Testing framework on its own.
    flags=""
    clt=/Library/Developer/CommandLineTools/Library/Developer
    if [ -d "$clt/Frameworks/Testing.framework" ] && ! xcodebuild -version >/dev/null 2>&1; then
        flags="-Xswiftc -F$clt/Frameworks -Xlinker -F$clt/Frameworks"
        flags="$flags -Xlinker -rpath -Xlinker $clt/Frameworks -Xlinker -rpath -Xlinker $clt/usr/lib"
    fi
    MAYI_CLI="$(cd "$root" && pwd)/target/release/mayi" swift test $flags
    exit
fi

swift build -c release
app=build/Mayi.app
rm -rf "$app"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp .build/release/Mayi "$app/Contents/MacOS/Mayi"
cp "$root/target/release/mayi" "$app/Contents/Resources/mayi"
cp -R "$root/skill" "$app/Contents/Resources/skill"
cp Info.plist "$app/Contents/Info.plist"
cp Mayi.icns "$app/Contents/Resources/Mayi.icns"
# Ad-hoc signature: enough to run locally, not to distribute.
codesign --force --sign - "$app"
echo "Built $app"

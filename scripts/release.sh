#!/bin/sh
# Builds every file of a release into dist/VERSION/:
#   Mayi-VERSION-macos-arm64.zip          the Mac app (ad-hoc signed)
#   mayi-VERSION-TARGET.tar.gz            the CLI and the agent skill, for
#                                         macOS arm64 and static Linux builds
#   mayi-VERSION-android.apk              the Android app, release-signed
#   SHA256SUMS
#
# The Android signing key is read from MAYI_KEYSTORE (default
# ~/.android/mayi-release.jks), its password from MAYI_KEYSTORE_PASSWORD or
# else the macOS keychain item "mayi-android-release". Every release must be
# signed with the same key, or installed copies cannot update.
set -eu
cd "$(dirname "$0")/.."
root=$PWD

if command -v cargo >/dev/null 2>&1; then run=""; else run="mise exec --"; fi
version=$(sed -n 's/^version = "\(.*\)"$/\1/p' Cargo.toml | head -1)
dist="$root/dist/$version"
rm -rf "$dist"
mkdir -p "$dist"

# The CLI, with the skill that teaches agents to use it.
pack() {
    binary=$1 target=$2
    name="mayi-$version-$target"
    stage=$(mktemp -d)
    mkdir -p "$stage/$name"
    cp "$binary" "$stage/$name/mayi"
    cp -R skill "$stage/$name/skill"
    tar -C "$stage" -czf "$dist/$name.tar.gz" "$name"
    rm -rf "$stage"
}

# Mac app (builds the CLI for this Mac as well).
apps/macos/build.sh
# Without the hardened runtime, another program could load its code into
# Mayi and read the keychain item that protects its keys.
codesign -dv apps/macos/build/Mayi.app 2>&1 | grep -q "flags=.*runtime" ||
    { echo "Mayi.app is not signed with the hardened runtime" >&2; exit 1; }
# Without extended attributes: as AppleDouble files they would break the
# app's seal when extracted with unzip.
ditto -c -k --norsrc --noextattr --keepParent apps/macos/build/Mayi.app "$dist/Mayi-$version-macos-arm64.zip"
pack target/release/mayi aarch64-apple-darwin

scripts/build-linux.sh
pack target/x86_64-unknown-linux-musl/release/mayi x86_64-unknown-linux-musl
pack target/aarch64-unknown-linux-musl/release/mayi aarch64-unknown-linux-musl

# Android.
export MAYI_KEYSTORE="${MAYI_KEYSTORE:-$HOME/.android/mayi-release.jks}"
if [ -z "${MAYI_KEYSTORE_PASSWORD:-}" ]; then
    MAYI_KEYSTORE_PASSWORD=$(security find-generic-password -s mayi-android-release -w)
fi
export MAYI_KEYSTORE_PASSWORD
apps/android/build-core.sh
(cd apps/android && $run ./gradlew --quiet assembleRelease)
cp apps/android/app/build/outputs/apk/release/app-release.apk "$dist/mayi-$version-android.apk"

(cd "$dist" && shasum -a 256 -- * > SHA256SUMS)
echo "Release files in $dist:"
ls -l "$dist"

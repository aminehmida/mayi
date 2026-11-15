// swift-tools-version: 6.0
import PackageDescription

// The Rust core is linked as a static library built by build.sh, which also
// generates the UniFFI header and Swift bindings.
let package = Package(
    name: "Mayi",
    platforms: [.macOS(.v14)],
    targets: [
        .target(name: "mayi_ffiFFI"),
        .target(
            name: "MayiKit",
            dependencies: ["mayi_ffiFFI"],
            // The archive by path: next to it sits a dynamic library built for
            // Android tooling, which `-lmayi_ffi` would pick up instead.
            linkerSettings: [.unsafeFlags(["../../target/release/libmayi_ffi.a"])]
        ),
        .executableTarget(name: "Mayi", dependencies: ["MayiKit"]),
        .testTarget(name: "MayiKitTests", dependencies: ["MayiKit"]),
    ],
    swiftLanguageModes: [.v5]
)

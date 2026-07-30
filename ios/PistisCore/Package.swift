// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "PistisCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "PistisCore", targets: ["PistisCore"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/apple/swift-crypto.git",
            exact: "4.5.1"
        ),
    ],
    targets: [
        .target(
            name: "PistisCore",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            resources: [.process("Resources")]
        ),
        .testTarget(name: "PistisCoreTests", dependencies: ["PistisCore"]),
    ]
)

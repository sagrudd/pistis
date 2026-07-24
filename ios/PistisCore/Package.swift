// swift-tools-version: 6.0

import PackageDescription

let package = Package(
    name: "PistisCore",
    platforms: [.iOS(.v17), .macOS(.v14)],
    products: [
        .library(name: "PistisCore", targets: ["PistisCore"]),
    ],
    targets: [
        .target(name: "PistisCore"),
        .testTarget(name: "PistisCoreTests", dependencies: ["PistisCore"]),
    ]
)

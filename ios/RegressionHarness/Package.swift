// swift-tools-version: 6.0
import PackageDescription

let package = Package(
  name: "PistisIOSConformanceHarness",
  products: [.executable(name: "pistis-ios-harness", targets: ["PistisHarnessCLI"])],
  dependencies: [
    .package(path: "../PistisCore"),
    .package(url: "https://github.com/apple/swift-crypto.git", exact: "4.5.1"),
    .package(url: "https://github.com/apple/swift-asn1.git", exact: "1.7.1"),
  ],
  targets: [
    .target(
      name: "Harness",
      dependencies: [
        .product(name: "PistisCore", package: "PistisCore"),
        .product(name: "Crypto", package: "swift-crypto"),
      ]
    ),
    .executableTarget(name: "PistisHarnessCLI", dependencies: ["Harness"]),
    .testTarget(name: "HarnessTests", dependencies: ["Harness"]),
  ]
)

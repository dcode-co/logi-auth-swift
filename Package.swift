// swift-tools-version: 6.3
import PackageDescription

// LogiAuth — drop-in "Sign in with logi" SDK for Relying Party iOS apps.
// Implements OAuth 2.0 Authorization Code + PKCE (RFC 7636) over
// ASWebAuthenticationSession (RFC 8252 system-browser requirement).
// When the logi app is installed, iOS routes the authorize URL via Universal
// Links so the user sees a native consent screen instead of a web page.
let package = Package(
    name: "LogiAuth",
    platforms: [
        .iOS(.v26),
    ],
    products: [
        .library(name: "LogiAuth", targets: ["LogiAuth"]),
    ],
    targets: [
        .target(
            name: "LogiAuth",
            path: "Sources/LogiAuth",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
        .testTarget(
            name: "LogiAuthTests",
            dependencies: ["LogiAuth"],
            path: "Tests/LogiAuthTests",
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)

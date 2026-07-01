// swift-tools-version: 6.3
import PackageDescription

// LogiAuth — drop-in "Sign in with logi" SDK for Relying Party iOS apps.
// Implements OAuth 2.0 Authorization Code + PKCE (RFC 7636 + RFC 8252).
//
// Sign-in flow (in order):
//   1. App-to-app handoff: UIApplication.open(authorizeURL, .universalLinksOnly:true).
//      When the logi app is installed AND its associated-domain entitlement matches,
//      iOS opens the logi app directly. The callback returns to the RP via the RP's
//      claimed Universal Link or custom URL scheme; the RP forwards it to LogiAuth
//      by calling `LogiAuth.handle(url:)` from `onOpenURL`.
//   2. ASWebAuthenticationSession fallback: when the logi app isn't installed
//      (universalLinksOnly returns false), the system browser loads the web
//      /oauth/authorize page and the callback closes back into the SDK.
//
// Why not rely on UL inside ASWebAuthenticationSession? Apple intentionally
// suppresses Universal Link app handoff inside ASWAS to keep OAuth flows
// self-contained. App-to-app must be attempted BEFORE opening ASWAS.
let package = Package(
    name: "LogiAuth",
    platforms: [
        // SDK minimum = iOS 17. Picked deliberately:
        //   - SDK consumers (RPs) span a wide deployment-target range; we
        //     pin to the lowest the implementation actually requires, NOT
        //     the logi-server iOS app's own target.
        //   - Code uses Duration / Task.sleep(for:) (iOS 16+) and standard
        //     async URLSession (iOS 15+). iOS 17 covers ~98% of the active
        //     B2B/enterprise iPhone fleet as of 2026 (Forasoft 2025-07
        //     adoption survey) and includes every currently-registered RP
        //     (ainote ios_native, krx_listing, easy_bracket, …).
        //   - Do NOT raise without a concrete API need; previous .v26 cut
        //     off ainote (iOS 17) and forced a hand-rolled OAuth
        //     coordinator (ainote 2026-05-12 incident). Do NOT drop below
        //     .v17 without first removing Duration usage in LogiAuth.swift
        //     (`Self.handoffTimeout`).
        .iOS(.v17),
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
            resources: [.copy("Fixtures/id-token-vectors.json")],
            swiftSettings: [.swiftLanguageMode(.v5)]
        ),
    ]
)

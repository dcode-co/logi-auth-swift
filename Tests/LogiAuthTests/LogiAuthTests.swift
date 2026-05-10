import XCTest
@testable import LogiAuth

final class LogiAuthTests: XCTestCase {
    func testPKCEPair() {
        let pair = PKCE.generate()
        XCTAssertGreaterThanOrEqual(pair.verifier.count, 43)
        XCTAssertLessThanOrEqual(pair.verifier.count, 128)
        XCTAssertEqual(pair.challenge.count, 43)  // SHA256 base64url no padding
        XCTAssertFalse(pair.verifier.contains("="))
        XCTAssertFalse(pair.challenge.contains("="))
    }

    func testConfigDefaults() {
        let cfg = LogiAuthConfig(
            clientId: "rp_test",
            redirectURI: URL(string: "https://rp.example.com/oauth/callback")!
        )
        XCTAssertEqual(cfg.issuer.absoluteString, "https://api.1pass.dev")
        XCTAssertEqual(cfg.scopes, ["openid", "profile:basic"])
    }

    /// `LogiAuth.handle(_:)` returns false when no sign-in is in flight, so
    /// RP apps can safely call it from `onOpenURL` for ALL incoming URLs
    /// without consuming non-LogiAuth deep links.
    @MainActor
    func testHandleWithoutPendingSignInReturnsFalse() {
        let consumed = LogiAuth.handle(URL(string: "easybracket://oauth/callback?code=x&state=y")!)
        XCTAssertFalse(consumed)
    }

    /// `LogiAuthError` covers the two new failure modes added for app-to-app
    /// handoff so RP apps can branch on them in their error UI.
    func testHandoffErrorsHaveDescriptions() {
        XCTAssertNotNil(LogiAuthError.handoffTimeout.errorDescription)
        XCTAssertNotNil(LogiAuthError.alreadyInProgress.errorDescription)
    }
}

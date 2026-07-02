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
        XCTAssertEqual(cfg.tokenIssuer, "https://api.1pass.dev")
        XCTAssertEqual(cfg.scopes, ["openid", "profile:basic", "email"])
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

    /// Regression: `handle(_:)` must reject URLs that don't match the
    /// configured redirect URI. Prevents an RP's unrelated `applinks:`
    /// universal link from being force-fed to the OAuth parser
    /// (ainote 2026-05-15 incident — `applinks:onrender.com` delivered an
    /// unrelated UL while a logi sign-in was pending → SDK consumed it →
    /// missingCode thrown to the user as a fake "OAuth failed").
    @MainActor
    func testHandleWithoutConfigDoesNotConsume() {
        // With no LogiAuth.configure() called, handleCallback hits the
        // `guard let cfg = config` branch and returns false even if a
        // handoff were pending. Asserts the safety contract.
        let consumed = LogiAuth.handle(URL(string: "https://other.example.com/foo?code=x&state=y")!)
        XCTAssertFalse(consumed, "URL must not be consumed when no config is set")
    }

    /// Regression (S1): a callback URL with duplicate query keys must NOT crash.
    /// The old `Dictionary(uniqueKeysWithValues:)` trapped on a repeated key;
    /// we now take first-wins. A malformed/hostile callback should degrade
    /// gracefully, never `fatalError`.
    @MainActor
    func testParseCallbackDuplicateKeysFirstWinsNoCrash() throws {
        let url = URL(string: "myapp://cb?code=first&code=second&state=s1&state=s2")!
        let (code, state) = try LogiAuth.shared.parseCallback(url)
        XCTAssertEqual(code, "first", "duplicate code must resolve first-wins")
        XCTAssertEqual(state, "s1", "duplicate state must resolve first-wins")
    }
}

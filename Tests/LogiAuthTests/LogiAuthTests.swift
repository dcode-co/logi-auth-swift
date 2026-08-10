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

    /// `cancel()` with nothing in flight is a no-op returning false. RP apps
    /// call it from scene-phase handlers that also fire when no sign-in is
    /// running, so it must be safe to call unconditionally.
    @MainActor
    func testCancelWithoutPendingSignInReturnsFalse() {
        XCTAssertFalse(LogiAuth.cancel())
    }

    /// `handoffKind` is nil when no sign-in is in flight — the RP gates
    /// `cancel()` on `== .native`, so a stale non-nil value would cancel a
    /// later sign-in that never started.
    @MainActor
    func testHandoffKindIsNilWhenIdle() {
        XCTAssertNil(LogiAuth.handoffKind)
    }

    /// The two routes must stay distinguishable. `.web` covers BOTH web shapes
    /// (HTTPS redirect + custom scheme) — the RP's decision is only ever
    /// "native handoff or not".
    func testHandoffKindCasesAreDistinct() {
        XCTAssertNotEqual(LogiHandoffKind.native, LogiHandoffKind.web)
        XCTAssertEqual(LogiHandoffKind.native.rawValue, "native")
        XCTAssertEqual(LogiHandoffKind.web.rawValue, "web")
    }

    /// Cancellation surfaces as the existing `.userCancelled`, NOT a new error
    /// case or `CancellationError`. RP apps already branch on it to suppress
    /// the error banner (ax_admin `LoginFailure.isUserCancellation`), and some
    /// match on the string — a new case would silently bypass those paths.
    func testCancelUsesUserCancelledError() {
        XCTAssertNotNil(LogiAuthError.userCancelled.errorDescription)
        XCTAssertTrue(String(describing: LogiAuthError.userCancelled).contains("userCancelled"))
    }

    /// Regression: the `.alreadyInProgress` guard must cover EVERY route.
    /// It used to test `pendingHandoff == nil`, which the custom-scheme ASWAS
    /// route never populates (its continuation lives in the completion
    /// handler). Two custom-scheme sign-ins could therefore run at once over
    /// the single `session` slot — the second overwrote the first, stranding
    /// the first continuation and pointing `cancel()` at the wrong flow.
    /// The guard now reads `signInInFlight`, which every route sets.
    @MainActor
    func testInFlightFlagIsResetWhenIdle() {
        XCTAssertFalse(LogiAuth.shared.signInInFlight, "no sign-in running — the guard must be open")
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

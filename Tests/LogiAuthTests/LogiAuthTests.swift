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
        // With nothing in flight, handleCallback returns false at the
        // `pendingHandoff` guard, which sits *ahead* of the config guard —
        // so this assertion holds whether or not a config is present. The
        // `guard let cfg = config` branch it documents is only reached once a
        // handoff is pending; keep that in mind before treating this test as
        // coverage of the unconfigured path.
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

    // MARK: - authorize(startURL:) — backend-led (BFF) flow

    /// `authorize(startURL:)` must refuse a URL with no `state`. The backend
    /// owns state in this flow, so its absence means the URL did not come from
    /// a `/start` call — and without it the SDK cannot tell this flow's
    /// callback from a stale or injected one.
    @MainActor
    func testAuthorizeRejectsStartURLWithoutState() async {
        let noState = URL(string: "https://api.1pass.dev/oauth/authorize?client_id=rp_test&code_challenge=abc")!
        do {
            _ = try await LogiAuth.authorize(startURL: noState)
            XCTFail("a startURL without state must not be opened")
        } catch let error as LogiAuthError {
            guard case .missingStateInStartURL = error else {
                return XCTFail("expected .missingStateInStartURL, got \(error)")
            }
        } catch {
            XCTFail("unexpected error type: \(error)")
        }
    }

    /// An empty `state=` is the same failure as a missing one — a blank value
    /// would match any callback.
    @MainActor
    func testAuthorizeRejectsEmptyState() async {
        let blank = URL(string: "https://api.1pass.dev/oauth/authorize?client_id=rp_test&state=")!
        do {
            _ = try await LogiAuth.authorize(startURL: blank)
            XCTFail("a blank state must not be accepted")
        } catch let error as LogiAuthError {
            guard case .missingStateInStartURL = error else {
                return XCTFail("expected .missingStateInStartURL, got \(error)")
            }
        } catch {
            XCTFail("unexpected error type: \(error)")
        }
    }

    /// The validation above must run BEFORE the single-flight lock is taken.
    /// Otherwise a malformed `startURL` would leave `signInInFlight` set and
    /// every later sign-in would throw `.alreadyInProgress`.
    @MainActor
    func testAuthorizeValidationDoesNotLeakTheSingleFlightLock() async {
        _ = try? await LogiAuth.authorize(
            startURL: URL(string: "https://api.1pass.dev/oauth/authorize?client_id=rp_test")!
        )
        XCTAssertFalse(
            LogiAuth.shared.signInInFlight,
            "a rejected startURL must not hold the lock — later sign-ins would be blocked forever"
        )
        XCTAssertNil(LogiAuth.handoffKind)
    }

    /// `LogiCallback` carries the callback pair and nothing else. Tokens and
    /// the PKCE verifier stay on the RP backend in this flow; if either ever
    /// appears on this type, the app is holding a secret it must not have.
    func testLogiCallbackCarriesOnlyCodeAndState() {
        let cb = LogiCallback(code: "the-code", state: "the-state")
        XCTAssertEqual(cb.code, "the-code")
        XCTAssertEqual(cb.state, "the-state")

        let mirrored = Mirror(reflecting: cb).children.compactMap(\.label).sorted()
        XCTAssertEqual(
            mirrored, ["code", "state"],
            "LogiCallback must not grow token or verifier fields — they belong to the backend"
        )
    }

    func testMissingStateInStartURLHasDescription() {
        XCTAssertNotNil(LogiAuthError.missingStateInStartURL.errorDescription)
    }

    /// Regression (S1): a callback URL with duplicate query keys must NOT crash.
    /// The old `Dictionary(uniqueKeysWithValues:)` trapped on a repeated key;
    /// we now take first-wins. A malformed/hostile callback should degrade
    /// gracefully, never `fatalError`.
    @MainActor
    func testParseCallbackDuplicateKeysFirstWinsNoCrash() throws {
        let url = URL(string: "myapp://cb?code=first&code=second&state=s1&state=s2")!
        let (code, state) = try LogiAuth.shared.parseCallback(url, expectedState: "s1")
        XCTAssertEqual(code, "first", "duplicate code must resolve first-wins")
        XCTAssertEqual(state, "s1", "duplicate state must resolve first-wins")
    }

    /// Regression: an unsolicited error callback must not be able to abort a
    /// live flow. `error` used to be handled before `state` was compared, so
    /// `myapp://cb?error=access_denied&state=wrong` cancelled someone else's
    /// sign-in. State is the only thing tying a callback to a flow, so it is
    /// checked first now. (codex review, 2026-08-10.)
    @MainActor
    func testParseCallbackChecksStateBeforeServerError() {
        let injected = URL(string: "myapp://cb?error=access_denied&state=wrong")!
        XCTAssertThrowsError(try LogiAuth.shared.parseCallback(injected, expectedState: "mine")) { error in
            guard case LogiAuthError.stateMismatch = error else {
                return XCTFail("expected .stateMismatch, got \(error)")
            }
        }
    }

    /// A genuine server error on a matching state still surfaces as such — the
    /// reordering above must not swallow real `access_denied` responses.
    @MainActor
    func testParseCallbackSurfacesServerErrorWhenStateMatches() {
        let denied = URL(string: "myapp://cb?error=access_denied&error_description=nope&state=mine")!
        XCTAssertThrowsError(try LogiAuth.shared.parseCallback(denied, expectedState: "mine")) { error in
            guard case LogiAuthError.authorizationServerError(let code, let desc) = error else {
                return XCTFail("expected .authorizationServerError, got \(error)")
            }
            XCTAssertEqual(code, "access_denied")
            XCTAssertEqual(desc, "nope")
        }
    }

    /// A callback with no state at all is a mismatch, not a missing code.
    @MainActor
    func testParseCallbackRejectsCallbackWithoutState() {
        let noState = URL(string: "myapp://cb?code=abc")!
        XCTAssertThrowsError(try LogiAuth.shared.parseCallback(noState, expectedState: "mine")) { error in
            guard case LogiAuthError.stateMismatch = error else {
                return XCTFail("expected .stateMismatch, got \(error)")
            }
        }
    }

    func testWebAuthSessionStartFailedHasDescription() {
        XCTAssertNotNil(LogiAuthError.webAuthSessionStartFailed.errorDescription)
    }
}

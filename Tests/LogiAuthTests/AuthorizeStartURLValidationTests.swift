import XCTest
@testable import LogiAuth

/// Pins the launch-time input validation of `authorize(startURL:nativeStartURL:)`
/// (v1.4.0 — the BFF edition of the host split).
///
/// The verdicts drive which error the caller gets **before anything is
/// launched**: no usable `state` → `.missingStateInStartURL`; a duplicated
/// `state`, or a pair that differs beyond the host → `.startURLPairMismatch`.
/// The full `authorize()` path needs a live flow (single-flight,
/// UIApplication), so what these tests pin are the decision functions
/// `readStartURLState` / `validateStartURLPair` — the wiring (validate before
/// the single-flight claim, launch only after both pass) is asserted by the
/// call order in `authorize()` itself.
final class AuthorizeStartURLValidationTests: XCTestCase {

    private func url(_ query: String) -> URL {
        URL(string: "https://api.1pass.dev/oauth/authorize?\(query)")!
    }

    func testSingleStateIsReadBack() {
        XCTAssertEqual(
            LogiAuth.readStartURLState(url("client_id=x&state=abc-123&scope=openid")),
            .one("abc-123")
        )
    }

    func testMissingStateIsMissing() {
        XCTAssertEqual(LogiAuth.readStartURLState(url("client_id=x&scope=openid")), .missing)
    }

    func testEmptyStateIsMissing() {
        XCTAssertEqual(LogiAuth.readStartURLState(url("state=&client_id=x")), .missing)
        XCTAssertEqual(LogiAuth.readStartURLState(url("state&client_id=x")), .missing)
    }

    /// Two `state` keys are ambiguity, not "first wins" — which one the server
    /// echoes back is server-dependent, and guessing wrong fails the callback
    /// match after the user has already authenticated.
    func testDuplicatedStateIsDuplicated() {
        XCTAssertEqual(LogiAuth.readStartURLState(url("state=a&state=a")), .duplicated)
        XCTAssertEqual(LogiAuth.readStartURLState(url("state=a&client_id=x&state=b")), .duplicated)
    }

    /// `statement=x` must not be mistaken for a `state` key.
    func testPrefixKeysDoNotCount() {
        XCTAssertEqual(LogiAuth.readStartURLState(url("statement=a&states=b")), .missing)
    }

    /// Percent-encoded values compare decoded (URLComponents.queryItems
    /// decodes), so the two legs match even when the state carries reserved
    /// characters.
    func testStateIsPercentDecoded() {
        XCTAssertEqual(LogiAuth.readStartURLState(url("state=a%20b")), .one("a b"))
    }

    // MARK: - validateStartURLPair

    private func swapHost(_ u: URL) -> URL {
        URL(string: u.absoluteString.replacingOccurrences(
            of: "api.1pass.dev", with: "open.1pass.dev"))!
    }

    /// The meetnote-shaped pair: the native leg derived from the web leg by a
    /// host swap → passes, and the shared state comes back.
    func testHostSwappedPairValidates() throws {
        let web = url("state=S1&code_challenge=C&code_challenge_method=S256")
        XCTAssertEqual(try LogiAuth.validateStartURLPair(startURL: web, nativeStartURL: swapHost(web)), "S1")
    }

    func testNilNativeLegValidatesAsSingleURL() throws {
        let web = url("state=S1&code_challenge=C")
        XCTAssertEqual(try LogiAuth.validateStartURLPair(startURL: web, nativeStartURL: nil), "S1")
    }

    func testMissingStateThrowsMissing() {
        XCTAssertThrowsError(try LogiAuth.validateStartURLPair(
            startURL: url("client_id=x"), nativeStartURL: nil)
        ) { XCTAssertEqual($0 as? LogiAuthError, .missingStateInStartURL) }
    }

    /// Duplicated `state` is a pair-contract violation, not a missing state —
    /// the caller must learn it built a bad URL, not that it forgot the state.
    func testDuplicatedStateThrowsPairMismatch() {
        XCTAssertThrowsError(try LogiAuth.validateStartURLPair(
            startURL: url("state=a&state=b"), nativeStartURL: nil)
        ) { XCTAssertEqual($0 as? LogiAuthError, .startURLPairMismatch) }
    }

    /// 🔴 Same state is NOT enough. A drifting `redirect_uri` strands the
    /// handoff until timeout; drifting PKCE fails the exchange after the user
    /// already authenticated. The whole query must be byte-identical.
    func testSameStateButDriftingQueryThrowsPairMismatch() {
        let web = url("state=S1&redirect_uri=a%3A%2F%2Fcb&code_challenge=C1")
        let drifted = URL(string:
            "https://open.1pass.dev/oauth/authorize?state=S1&redirect_uri=b%3A%2F%2Fcb&code_challenge=C1")!
        XCTAssertThrowsError(try LogiAuth.validateStartURLPair(
            startURL: web, nativeStartURL: drifted)
        ) { XCTAssertEqual($0 as? LogiAuthError, .startURLPairMismatch) }
    }

    func testDifferentPathThrowsPairMismatch() {
        let web = url("state=S1")
        let wrongPath = URL(string: "https://open.1pass.dev/oauth/authorize2?state=S1")!
        XCTAssertThrowsError(try LogiAuth.validateStartURLPair(
            startURL: web, nativeStartURL: wrongPath)
        ) { XCTAssertEqual($0 as? LogiAuthError, .startURLPairMismatch) }
    }

    /// v1.4.1 — the web fallback's cookie policy is config-driven. Default
    /// stays ephemeral (every pre-1.4.1 RP shipped that way); `false` opts into
    /// shared Safari cookies for RPs whose fallback is the whole login.
    func testPrefersEphemeralWebSessionDefaultsTrueAndIsOverridable() {
        let stock = LogiAuthConfig(
            clientId: "logi_x", redirectURI: URL(string: "x://cb")!)
        XCTAssertTrue(stock.prefersEphemeralWebSession)

        let shared = LogiAuthConfig(
            clientId: "logi_x", redirectURI: URL(string: "x://cb")!,
            prefersEphemeralWebSession: false)
        XCTAssertFalse(shared.prefersEphemeralWebSession)
    }

    /// Only the host may differ — that is the entire point of the pair.
    func testDifferentPortThrowsPairMismatch() {
        let web = url("state=S1")
        let wrongPort = URL(string: "https://open.1pass.dev:8443/oauth/authorize?state=S1")!
        XCTAssertThrowsError(try LogiAuth.validateStartURLPair(
            startURL: web, nativeStartURL: wrongPort)
        ) { XCTAssertEqual($0 as? LogiAuthError, .startURLPairMismatch) }
    }
}

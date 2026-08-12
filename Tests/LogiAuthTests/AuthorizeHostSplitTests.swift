import XCTest
@testable import LogiAuth

/// Pins the v1.3.0 authorize host split: `signIn()` sends its **native
/// app-to-app handoff** to `open.1pass.dev` (which claims `/oauth/authorize*`
/// in its AASA) while its **web fallback** stays on `api.1pass.dev` (which must
/// not, or the claim hijacks the browser flow).
///
/// The split is a two-sided invariant, and both sides are load-bearing:
///   - native on the claimed host, or app-to-app SSO never launches the app;
///   - web on the unclaimed host, or every user **without** the logi app
///     installed loses sign-in entirely — the web leg is their only leg.
///
/// `issuer` is not part of the split. Token exchange, JWKS, and the `iss` check
/// stay on it; moving `issuer` would break the code redemption for everyone.
final class AuthorizeHostSplitTests: XCTestCase {
    private let apiHost = "api.1pass.dev"
    private let openHost = "open.1pass.dev"

    private func makeConfig(
        issuer: URL = LogiAuthConfig.defaultIssuer,
        nativeAuthorizeHost: String? = nil
    ) -> LogiAuthConfig {
        LogiAuthConfig(
            clientId: "rp_test",
            redirectURI: URL(string: "https://rp.example.com/oauth/callback")!,
            issuer: issuer,
            nativeAuthorizeHost: nativeAuthorizeHost
        )
    }

    private func makeURLs(_ config: LogiAuthConfig, scopes: [String]? = nil) throws -> (native: URL, web: URL) {
        try LogiAuth.makeAuthorizeURLs(
            config: config,
            scopes: scopes,
            state: "the-state",
            nonce: "the-nonce",
            codeChallenge: "the-challenge"
        )
    }

    // MARK: - The split itself

    /// Stock production config: native → open, web → api.
    func testStockIssuerSplitsNativeToOpenAndWebToApi() throws {
        let urls = try makeURLs(makeConfig())

        XCTAssertEqual(urls.native.host, openHost, "native handoff must target the host that claims /oauth/authorize*")
        XCTAssertEqual(urls.web.host, apiHost, "web fallback must stay on the issuer host")
        XCTAssertEqual(urls.native.path, "/oauth/authorize")
        XCTAssertEqual(urls.web.path, "/oauth/authorize")
        XCTAssertEqual(urls.native.scheme, "https")
        XCTAssertEqual(urls.web.scheme, "https")
    }

    /// 🔴 The regression this whole change exists to prevent, stated as its own
    /// assertion: if the web fallback URL is ever built on the claimed host,
    /// every user **without** the logi app installed loses sign-in — the AASA
    /// claim intercepts the page load they depend on and hands them to an app
    /// they do not have, or bounces the callback into a browser that holds no
    /// session. This must fail loudly the moment someone "simplifies" the two
    /// URLs back into one.
    func testWebFallbackIsNeverOnTheClaimedHandoffHost() throws {
        let urls = try makeURLs(makeConfig())

        XCTAssertNotEqual(
            urls.web.host, openHost,
            "web fallback on the claimed host kills sign-in for every user without the logi app installed"
        )
        XCTAssertNotEqual(
            urls.web.host, urls.native.host,
            "the two legs must address different hosts for the stock production issuer"
        )
        XCTAssertNotEqual(
            urls.web.absoluteString, urls.native.absoluteString,
            "a single URL for both legs is the pre-1.3.0 behaviour the split replaces"
        )
    }

    /// The two legs must be the **same authorization request**. Anything but
    /// the host differing — a re-ordered query, a second `state`, a dropped
    /// `nonce` — would make the fallback a different request than the one the
    /// caller is tracking, and the callback would fail `state` matching.
    func testBothLegsCarryAnIdenticalQuery() throws {
        let urls = try makeURLs(makeConfig())

        XCTAssertEqual(urls.native.query, urls.web.query, "native and web must carry a byte-identical query string")

        let nativeItems = URLComponents(url: urls.native, resolvingAgainstBaseURL: false)?.queryItems
        let webItems = URLComponents(url: urls.web, resolvingAgainstBaseURL: false)?.queryItems
        XCTAssertEqual(nativeItems, webItems)

        // And it is the real authorize request, not an empty one that would
        // make the comparison above vacuously true.
        let items = try XCTUnwrap(webItems)
        let byName = Dictionary(items.compactMap { item in item.value.map { (item.name, $0) } }, uniquingKeysWith: { first, _ in first })
        XCTAssertEqual(byName["response_type"], "code")
        XCTAssertEqual(byName["client_id"], "rp_test")
        XCTAssertEqual(byName["redirect_uri"], "https://rp.example.com/oauth/callback")
        XCTAssertEqual(byName["state"], "the-state")
        XCTAssertEqual(byName["nonce"], "the-nonce")
        XCTAssertEqual(byName["code_challenge"], "the-challenge")
        XCTAssertEqual(byName["code_challenge_method"], "S256")
        XCTAssertEqual(byName["scope"], "openid profile:basic email")
    }

    /// Per-call scope override lands on both legs, still identically.
    func testScopeOverrideAppliesToBothLegs() throws {
        let urls = try makeURLs(makeConfig(), scopes: ["openid", "email"])

        XCTAssertEqual(urls.native.query, urls.web.query)
        XCTAssertTrue(try XCTUnwrap(urls.web.query).contains("scope=openid%20email"))
    }

    // MARK: - Non-stock deployments must not be derived

    /// A staging or self-hosted issuer gets **one** host for both legs.
    /// `open.1pass.dev` is a production host: deriving it for a staging RP would
    /// send the authorize request to the wrong deployment entirely.
    func testStagingIssuerKeepsBothLegsOnItsOwnHost() throws {
        let staging = URL(string: "https://api.staging.1pass.dev")!
        let urls = try makeURLs(makeConfig(issuer: staging))

        XCTAssertEqual(urls.native.host, "api.staging.1pass.dev")
        XCTAssertEqual(urls.web.host, "api.staging.1pass.dev")
        XCTAssertNotEqual(urls.native.host, openHost, "a staging deployment must never be pointed at the production bouncer")
        XCTAssertEqual(urls.native.absoluteString, urls.web.absoluteString, "no split without a host we know claims the path")
    }

    /// Same for a fully self-hosted deployment on an unrelated domain.
    func testSelfHostedIssuerKeepsBothLegsOnItsOwnHost() throws {
        let selfHosted = URL(string: "https://id.example.co.kr")!
        let urls = try makeURLs(makeConfig(issuer: selfHosted))

        XCTAssertEqual(urls.native.host, "id.example.co.kr")
        XCTAssertEqual(urls.web.host, "id.example.co.kr")
        XCTAssertEqual(urls.native.absoluteString, urls.web.absoluteString)
    }

    /// A self-hosted deployment that *does* run a bouncer says so explicitly,
    /// and that wins over any derivation.
    func testExplicitNativeAuthorizeHostOverridesDerivation() throws {
        let selfHosted = URL(string: "https://id.example.co.kr")!
        let urls = try makeURLs(makeConfig(issuer: selfHosted, nativeAuthorizeHost: "open.example.co.kr"))

        XCTAssertEqual(urls.native.host, "open.example.co.kr")
        XCTAssertEqual(urls.web.host, "id.example.co.kr", "an explicit handoff host must not drag the web leg with it")
        XCTAssertEqual(urls.native.query, urls.web.query)
    }

    /// An explicit host also overrides the stock derivation — an RP pinned to a
    /// different bouncer is not silently redirected to `open.1pass.dev`.
    func testExplicitHostOverridesEvenForStockIssuer() throws {
        let urls = try makeURLs(makeConfig(nativeAuthorizeHost: "open.test.1pass.dev"))

        XCTAssertEqual(urls.native.host, "open.test.1pass.dev")
        XCTAssertEqual(urls.web.host, apiHost)
    }

    /// An empty string is not a host. It must fall through to derivation rather
    /// than producing a hostless (and unopenable) URL.
    func testEmptyNativeAuthorizeHostFallsBackToDerivation() throws {
        let urls = try makeURLs(makeConfig(nativeAuthorizeHost: ""))

        XCTAssertEqual(urls.native.host, openHost)
        XCTAssertEqual(urls.web.host, apiHost)
    }

    /// Host comparison is case-insensitive on the issuer side — DNS is, and an
    /// RP that configured `https://API.1pass.dev` is still on stock production.
    func testIssuerHostMatchIsCaseInsensitive() throws {
        let shouty = URL(string: "https://API.1pass.dev")!
        let urls = try makeURLs(makeConfig(issuer: shouty))

        XCTAssertEqual(urls.native.host, openHost)
        XCTAssertEqual(urls.web.host?.lowercased(), apiHost, "the web leg is left on the issuer the RP configured")
    }

    /// Config-level view of the same rule, so a change to the resolver is
    /// caught even if `makeAuthorizeURLs` is refactored away from it.
    func testResolvedNativeAuthorizeHostRules() {
        XCTAssertEqual(makeConfig().resolvedNativeAuthorizeHost, openHost)
        XCTAssertEqual(makeConfig(nativeAuthorizeHost: "custom.example.com").resolvedNativeAuthorizeHost, "custom.example.com")
        XCTAssertEqual(
            makeConfig(issuer: URL(string: "https://api.staging.1pass.dev")!).resolvedNativeAuthorizeHost,
            "api.staging.1pass.dev"
        )
        XCTAssertEqual(LogiAuthConfig.defaultNativeAuthorizeHost, openHost)
        XCTAssertEqual(LogiAuthConfig.defaultIssuer.host, apiHost)
    }

    // MARK: - What the split must NOT move

    /// 🔴 The handoff host moves the authorize leg and nothing else. The
    /// authorization code is redeemed at `issuer`; sending the exchange to the
    /// bouncer host would break every sign-in that reaches it. Asserted against
    /// the same helper the live request uses, not a re-derivation.
    func testTokenExchangeStaysOnIssuerEvenWhenHandoffIsSplit() {
        let cfg = makeConfig()
        XCTAssertEqual(cfg.resolvedNativeAuthorizeHost, openHost, "precondition: this config IS split")

        let tokenURL = LogiAuth.tokenEndpoint(issuer: cfg.issuer)
        XCTAssertEqual(tokenURL.host, apiHost)
        XCTAssertEqual(tokenURL.absoluteString, "https://api.1pass.dev/oauth/token")
    }

    /// Same for JWKS — the signing keys belong to the issuer.
    func testJWKSStaysOnIssuerEvenWhenHandoffIsSplit() throws {
        let cfg = makeConfig()
        let jwksURL = try LogiAuth.jwksEndpoint(issuer: cfg.issuer)

        XCTAssertEqual(jwksURL.host, apiHost)
        XCTAssertEqual(jwksURL.absoluteString, "https://api.1pass.dev/.well-known/jwks.json")
    }

    /// A trailing slash on the issuer must not produce a double slash in the
    /// JWKS path — covered here because the endpoint builder was extracted for
    /// these tests and this was the reason it had trimming logic.
    func testJWKSEndpointTrimsTrailingSlash() throws {
        let jwksURL = try LogiAuth.jwksEndpoint(issuer: URL(string: "https://api.1pass.dev/")!)
        XCTAssertEqual(jwksURL.absoluteString, "https://api.1pass.dev/.well-known/jwks.json")
    }

    /// `tokenIssuer` — the expected `iss` claim inside the id_token — is not
    /// touched by the handoff split either. A token minted by the IdP always
    /// says `api.1pass.dev`, whichever host the user was handed off through.
    func testTokenIssuerClaimIsUnaffectedByTheSplit() {
        let cfg = makeConfig()
        XCTAssertEqual(cfg.tokenIssuer, "https://api.1pass.dev")
        XCTAssertEqual(cfg.issuer.absoluteString, "https://api.1pass.dev")

        let split = makeConfig(nativeAuthorizeHost: "open.1pass.dev")
        XCTAssertEqual(split.tokenIssuer, "https://api.1pass.dev", "setting a handoff host must not move the expected iss")
        XCTAssertEqual(split.issuer.absoluteString, "https://api.1pass.dev")
    }

    /// The default config is unchanged for RPs that never heard of this
    /// setting: `nativeAuthorizeHost` is opt-in and nil by default, and the
    /// derivation is what turns it on for stock production.
    func testNativeAuthorizeHostIsNilByDefault() {
        XCTAssertNil(makeConfig().nativeAuthorizeHost)
    }
}

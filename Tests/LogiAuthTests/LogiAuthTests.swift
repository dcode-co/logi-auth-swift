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
}

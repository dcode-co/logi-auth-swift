import XCTest
@testable import LogiAuth

/// Golden-vector parity test. The vectors in `Fixtures/id-token-vectors.json`
/// are a copy of the 4-SDK shared set (`test-vectors/id-token-vectors.json`,
/// SoT = generate.mjs). iOS MUST produce identical verify/reject results to
/// Web/Android/Flutter. JWKS is a fixed snapshot so this runs fully offline.
final class IdTokenVerifierTests: XCTestCase {

    private struct Vectors: Decodable {
        let now: TimeInterval
        let expected: Expected
        let jwks: JWKS
        let cases: [Case]
        struct Expected: Decodable { let issuer: String; let clientId: String; let nonce: String? }
        struct Case: Decodable { let name: String; let token: String; let expect: Expect }
        struct Expect: Decodable { let valid: Bool; let sub: String?; let error: String? }
    }

    private func loadVectors() throws -> Vectors {
        guard let url = Bundle.module.url(forResource: "id-token-vectors", withExtension: "json") else {
            XCTFail("golden vectors fixture missing from test bundle")
            throw NSError(domain: "test", code: 1)
        }
        let data = try Data(contentsOf: url)
        return try JSONDecoder().decode(Vectors.self, from: data)
    }

    func testGoldenVectors() throws {
        let v = try loadVectors()
        let expected = VerifyExpected(
            issuer: v.expected.issuer,
            clientId: v.expected.clientId,
            nonce: v.expected.nonce
        )

        for c in v.cases {
            do {
                let result = try verifyIdToken(c.token, jwks: v.jwks, expected: expected, now: v.now)
                XCTAssertTrue(c.expect.valid, "case '\(c.name)' expected to be invalid but verified")
                if let wantSub = c.expect.sub {
                    XCTAssertEqual(result.sub, wantSub, "case '\(c.name)' sub mismatch")
                }
            } catch let error as IdTokenVerifyError {
                XCTAssertFalse(c.expect.valid, "case '\(c.name)' expected valid but threw \(error.code)")
                if let wantError = c.expect.error {
                    XCTAssertEqual(error.code, wantError, "case '\(c.name)' error code mismatch")
                }
            }
        }
    }

    /// Sanity: at least the full 9-case set is present so a truncated fixture
    /// can't silently pass with zero assertions.
    func testGoldenVectorCoverage() throws {
        let v = try loadVectors()
        XCTAssertGreaterThanOrEqual(v.cases.count, 9, "expected the full golden-vector set")
        XCTAssertTrue(v.cases.contains { $0.name == "valid" })
    }
}

import XCTest
import Foundation
import Security
import CryptoKit
@testable import LogiAuth

/// S3 (at_hash present-only binding) and S4 (JWKS kty filter) coverage.
/// Tokens are signed inline with a freshly generated RSA key so the tests are
/// self-contained (no shared golden fixture — those are synced at integration).
final class AtHashAndKtyTests: XCTestCase {

    // MARK: - Inline RSA signing helpers

    /// Generate an ephemeral RSA-2048 keypair and return the private SecKey plus
    /// the JWK modulus/exponent (base64url, no padding) for the public half.
    private static func makeRSAKeyPair() throws -> (priv: SecKey, n: String, e: String) {
        let attrs: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048,
            kSecAttrIsPermanent: false,
        ]
        var err: Unmanaged<CFError>?
        guard let priv = SecKeyCreateRandomKey(attrs as CFDictionary, &err) else {
            throw XCTSkip("RSA keygen unavailable: \(err!.takeRetainedValue())")
        }
        let pub = SecKeyCopyPublicKey(priv)!
        guard let der = SecKeyCopyExternalRepresentation(pub, &err) as Data? else {
            throw XCTSkip("public key export unavailable")
        }
        let (n, e) = try parsePKCS1(der)
        return (priv, base64urlNoPad(n), base64urlNoPad(e))
    }

    /// Parse a PKCS#1 `RSAPublicKey` DER (SEQUENCE { INTEGER n, INTEGER e }) into
    /// the raw modulus/exponent bytes (leading sign byte stripped).
    private static func parsePKCS1(_ der: Data) throws -> (Data, Data) {
        let bytes = [UInt8](der)
        var idx = 0
        func readLen() -> Int {
            let first = Int(bytes[idx]); idx += 1
            if first < 0x80 { return first }
            let count = first & 0x7f
            var len = 0
            for _ in 0..<count { len = (len << 8) | Int(bytes[idx]); idx += 1 }
            return len
        }
        guard bytes[idx] == 0x30 else { throw NSError(domain: "der", code: 1) }
        idx += 1; _ = readLen()                       // SEQUENCE
        guard bytes[idx] == 0x02 else { throw NSError(domain: "der", code: 2) }
        idx += 1
        let nLen = readLen()
        var n = Array(bytes[idx..<idx + nLen]); idx += nLen
        guard bytes[idx] == 0x02 else { throw NSError(domain: "der", code: 3) }
        idx += 1
        let eLen = readLen()
        var e = Array(bytes[idx..<idx + eLen]); idx += eLen
        if n.first == 0x00 { n.removeFirst() }
        if e.first == 0x00 { e.removeFirst() }
        return (Data(n), Data(e))
    }

    private static func base64urlNoPad(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Server's at_hash: base64url(left-128-bits(SHA256(access_token))).
    private static func atHash(_ accessToken: String) -> String {
        let digest = SHA256.hash(data: Data(accessToken.utf8))
        return base64urlNoPad(Data(digest.prefix(16)))
    }

    private static func makeToken(payload: [String: Any], kid: String, priv: SecKey) throws -> String {
        let header: [String: Any] = ["alg": "RS256", "kid": kid, "typ": "JWT"]
        let h = base64urlNoPad(try JSONSerialization.data(withJSONObject: header))
        let p = base64urlNoPad(try JSONSerialization.data(withJSONObject: payload))
        let signingInput = "\(h).\(p)"
        var err: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(
            priv, .rsaSignatureMessagePKCS1v15SHA256, Data(signingInput.utf8) as CFData, &err
        ) as Data? else {
            throw NSError(domain: "sign", code: 1)
        }
        return "\(signingInput).\(base64urlNoPad(sig))"
    }

    private let now: TimeInterval = 1_700_000_000
    private let issuer = "https://api.1pass.dev"
    private let clientId = "rp_test"

    private func basePayload(atHash: String?) -> [String: Any] {
        var p: [String: Any] = [
            "iss": issuer,
            "aud": clientId,
            "exp": now + 300,
            "iat": now,
            "sub": "user-42",
        ]
        if let atHash { p["at_hash"] = atHash }
        return p
    }

    // MARK: - S3 at_hash

    func testAtHashValidBinding() throws {
        let (priv, n, e) = try Self.makeRSAKeyPair()
        let kid = "k1"
        let jwks = JWKS(keys: [JWK(kty: "RSA", n: n, e: e, kid: kid, alg: "RS256", use: "sig")])
        let accessToken = "access-token-abc123"
        let token = try Self.makeToken(payload: basePayload(atHash: Self.atHash(accessToken)), kid: kid, priv: priv)
        let expected = VerifyExpected(issuer: issuer, clientId: clientId)

        let verified = try verifyIdToken(token, jwks: jwks, expected: expected, now: now, accessToken: accessToken)
        XCTAssertEqual(verified.sub, "user-42")
    }

    func testAtHashMismatchRejects() throws {
        let (priv, n, e) = try Self.makeRSAKeyPair()
        let kid = "k1"
        let jwks = JWKS(keys: [JWK(kty: "RSA", n: n, e: e, kid: kid, alg: "RS256", use: "sig")])
        // Token bound to one access_token, but a DIFFERENT one is presented.
        let token = try Self.makeToken(payload: basePayload(atHash: Self.atHash("real-access-token")), kid: kid, priv: priv)
        let expected = VerifyExpected(issuer: issuer, clientId: clientId)

        XCTAssertThrowsError(
            try verifyIdToken(token, jwks: jwks, expected: expected, now: now, accessToken: "attacker-swapped-token")
        ) { error in
            XCTAssertEqual((error as? IdTokenVerifyError)?.code, "at_hash_mismatch")
        }
    }

    /// present-only: an at_hash is ignored when the caller supplies no
    /// access_token (e.g. verifying an id_token alone). Keeps v1.0.1 non-breaking.
    func testAtHashSkippedWhenNoAccessToken() throws {
        let (priv, n, e) = try Self.makeRSAKeyPair()
        let kid = "k1"
        let jwks = JWKS(keys: [JWK(kty: "RSA", n: n, e: e, kid: kid, alg: "RS256", use: "sig")])
        let token = try Self.makeToken(payload: basePayload(atHash: Self.atHash("some-token")), kid: kid, priv: priv)
        let expected = VerifyExpected(issuer: issuer, clientId: clientId)

        let verified = try verifyIdToken(token, jwks: jwks, expected: expected, now: now)  // no accessToken
        XCTAssertEqual(verified.sub, "user-42")
    }

    /// No at_hash claim + access_token provided → skip (nothing to bind).
    func testNoAtHashClaimSkips() throws {
        let (priv, n, e) = try Self.makeRSAKeyPair()
        let kid = "k1"
        let jwks = JWKS(keys: [JWK(kty: "RSA", n: n, e: e, kid: kid, alg: "RS256", use: "sig")])
        let token = try Self.makeToken(payload: basePayload(atHash: nil), kid: kid, priv: priv)
        let expected = VerifyExpected(issuer: issuer, clientId: clientId)

        let verified = try verifyIdToken(token, jwks: jwks, expected: expected, now: now, accessToken: "irrelevant")
        XCTAssertEqual(verified.sub, "user-42")
    }

    // MARK: - S4 kty filter

    /// An EC key sharing the signing kid must not shadow the RSA key. Without the
    /// kty filter, `first(where: kid)` would pick the EC entry and fail signature
    /// verification (bad_signature); with it, the RSA key is selected and the
    /// token verifies.
    func testKtyFilterSelectsRSAWhenECShareKid() throws {
        let (priv, n, e) = try Self.makeRSAKeyPair()
        let kid = "shared-kid"
        // EC decoy first (dummy n/e — filtered out by kty != RSA), RSA second.
        let ecDecoy = JWK(kty: "EC", n: "AAAA", e: "AQAB", kid: kid, alg: nil, use: nil)
        let rsaKey = JWK(kty: "RSA", n: n, e: e, kid: kid, alg: "RS256", use: "sig")
        let jwks = JWKS(keys: [ecDecoy, rsaKey])
        let token = try Self.makeToken(payload: basePayload(atHash: nil), kid: kid, priv: priv)
        let expected = VerifyExpected(issuer: issuer, clientId: clientId)

        let verified = try verifyIdToken(token, jwks: jwks, expected: expected, now: now)
        XCTAssertEqual(verified.sub, "user-42")
    }

    /// Real mixed JWKS: an EC key (crv/x/y, NO RSA n/e) alongside the RSA signing
    /// key, decoded from JSON. Lenient JWKS decoding must drop the EC entry
    /// instead of failing the whole decode, and the RSA key must still verify.
    /// (Regression for the strict-decode gap: a strict `[JWK]` decode would throw
    /// on the EC key before the kty filter ever ran.)
    func testJWKSDecodeTolerantOfECKeyAndRSAVerifies() throws {
        let (priv, n, e) = try Self.makeRSAKeyPair()
        let kid = "shared-kid"
        let json = """
        {"keys":[
          {"kty":"EC","crv":"P-256","x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU","y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0","kid":"\(kid)","use":"sig"},
          {"kty":"RSA","n":"\(n)","e":"\(e)","kid":"\(kid)","alg":"RS256","use":"sig"}
        ]}
        """
        let jwks = try JSONDecoder().decode(JWKS.self, from: Data(json.utf8))
        // EC entry dropped by lenient decode; only the RSA key survives.
        XCTAssertEqual(jwks.keys.count, 1)
        XCTAssertEqual(jwks.keys.first?.kty, "RSA")

        let token = try Self.makeToken(payload: basePayload(atHash: nil), kid: kid, priv: priv)
        let expected = VerifyExpected(issuer: issuer, clientId: clientId)
        let verified = try verifyIdToken(token, jwks: jwks, expected: expected, now: now)
        XCTAssertEqual(verified.sub, "user-42")
    }
}

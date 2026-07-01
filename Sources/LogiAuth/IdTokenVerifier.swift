import Foundation
import Security

// RS256 id_token 검증 — Security.framework(SecKey), zero third-party deps.
// 서버 검증 규칙 mirror: logi server/app/lib/oauth/jwt_verifier.rb
//   kid 필수 → JWKS 조회 → RS256 서명검증 → iss · aud · exp · iat · nonce · sub.
// 4플랫폼 공통 골든 벡터(../../test-vectors/id-token-vectors.json)를 동일 통과해야 함.
//
// 왜 서드파티 JWT 라이브러리를 안 쓰나: Web 검증기가 WebCrypto(zero-dep)를 쓴 것과
// 대칭. RP 앱에 전이 의존성을 강요하지 않는 "얇은 커넥터" 원칙. RSA 공개키는 JWK
// (n,e)로부터 PKCS#1 DER을 직접 구성해 SecKeyCreateWithData로 만든다.
//
// 주의: 이 SDK는 public client(backend 없는 모바일/SPA)용 자체 검증 경로다. backend
// 있는 confidential RP는 backend가 검증하는 게 표준이며 이 함수를 쓸 필요가 없다.

/// Failure reasons for id_token verification. `code` mirrors the Web verifier's
/// `VerifyErrorCode` and the golden-vector `error` strings exactly.
public enum IdTokenVerifyError: Error, Equatable, Sendable {
    case malformed
    case missingKid
    case unknownKid
    case badSignature
    case issMismatch
    case audMismatch
    case expired
    case nonceMismatch
    case missingClaim

    /// Stable machine code, identical across the 4 SDKs.
    public var code: String {
        switch self {
        case .malformed:     return "malformed"
        case .missingKid:    return "missing_kid"
        case .unknownKid:    return "unknown_kid"
        case .badSignature:  return "bad_signature"
        case .issMismatch:   return "iss_mismatch"
        case .audMismatch:   return "aud_mismatch"
        case .expired:       return "expired"
        case .nonceMismatch: return "nonce_mismatch"
        case .missingClaim:  return "missing_claim"
        }
    }
}

// MARK: - JWKS

public struct JWK: Decodable, Sendable {
    public let kty: String
    public let n: String
    public let e: String
    public let kid: String
    public let alg: String?
    public let use: String?
}

public struct JWKS: Decodable, Sendable {
    public let keys: [JWK]
    public init(keys: [JWK]) { self.keys = keys }
}

public struct VerifyExpected: Sendable {
    /// id_token.iss must equal this (logi issuer — the string "logi", NOT a URL).
    public let issuer: String
    /// id_token.aud must contain this (the RP's client_id).
    public let clientId: String
    /// If set, id_token.nonce must equal this (the value sent in authorize).
    public let nonce: String?

    public init(issuer: String, clientId: String, nonce: String? = nil) {
        self.issuer = issuer
        self.clientId = clientId
        self.nonce = nonce
    }
}

public struct VerifiedIdToken {
    public let sub: String
    public let claims: [String: Any]
}

/// Verify a logi-issued id_token and return its verified subject.
/// Throws `IdTokenVerifyError` on any failure. Never returns an unverified subject.
///
/// Claim check order matches the server (`jwt_verifier.rb`) and the Web verifier:
///   signature → iss → aud → exp → iat → nonce → sub.
///
/// - Parameters:
///   - now: Unix seconds; defaults to now. Injectable for deterministic tests.
///   - clockSkewSec: Allowed clock skew in seconds (default 60).
public func verifyIdToken(
    _ idToken: String,
    jwks: JWKS,
    expected: VerifyExpected,
    now: TimeInterval = Date().timeIntervalSince1970,
    clockSkewSec: TimeInterval = 60
) throws -> VerifiedIdToken {
    let parts = idToken
        .split(separator: ".", omittingEmptySubsequences: false)
        .map(String.init)
    guard parts.count == 3, !parts[0].isEmpty, !parts[1].isEmpty, !parts[2].isEmpty else {
        throw IdTokenVerifyError.malformed
    }

    guard
        let headerData = base64urlDecode(parts[0]),
        let header = (try? JSONSerialization.jsonObject(with: headerData)) as? [String: Any]
    else { throw IdTokenVerifyError.malformed }

    guard
        let payloadData = base64urlDecode(parts[1]),
        let payload = (try? JSONSerialization.jsonObject(with: payloadData)) as? [String: Any]
    else { throw IdTokenVerifyError.malformed }

    // Only RS256 is accepted — never verify a token whose header declares
    // another (or no) algorithm, even if the RSA signature happens to match.
    guard (header["alg"] as? String) == "RS256" else {
        throw IdTokenVerifyError.badSignature
    }

    // kid → JWKS key.
    guard let kid = header["kid"] as? String, !kid.isEmpty else {
        throw IdTokenVerifyError.missingKid
    }
    guard let jwk = jwks.keys.first(where: { $0.kid == kid }) else {
        throw IdTokenVerifyError.unknownKid
    }

    // RS256 signature verification via SecKey (no dependency).
    guard let signature = base64urlDecode(parts[2]) else {
        throw IdTokenVerifyError.badSignature
    }
    let publicKey = try rsaPublicKey(from: jwk)
    let signingInput = Data("\(parts[0]).\(parts[1])".utf8)
    var sigError: Unmanaged<CFError>?
    let sigOk = SecKeyVerifySignature(
        publicKey,
        .rsaSignatureMessagePKCS1v15SHA256,
        signingInput as CFData,
        signature as CFData,
        &sigError
    )
    guard sigOk else { throw IdTokenVerifyError.badSignature }

    // Claim checks (order: iss → aud → exp → iat → nonce → sub).
    guard (payload["iss"] as? String) == expected.issuer else {
        throw IdTokenVerifyError.issMismatch
    }

    if !audienceMatches(payload["aud"], clientId: expected.clientId) {
        throw IdTokenVerifyError.audMismatch
    }

    // OIDC §3.1.3.7 azp: with multiple audiences an azp MUST be present; whenever
    // azp is present it MUST equal our client_id.
    let azp = payload["azp"]
    if let audArray = payload["aud"] as? [Any], audArray.count > 1 {
        guard (azp as? String) == expected.clientId else { throw IdTokenVerifyError.audMismatch }
    } else if azp != nil && !(azp is NSNull) {
        guard (azp as? String) == expected.clientId else { throw IdTokenVerifyError.audMismatch }
    }

    guard let exp = numericClaim(payload["exp"]), exp > now - clockSkewSec else {
        throw IdTokenVerifyError.expired
    }

    guard let iat = numericClaim(payload["iat"]), iat <= now + clockSkewSec else {
        // iat missing or in the future → treat as malformed (mirrors Web verifier).
        throw IdTokenVerifyError.malformed
    }

    if let expectedNonce = expected.nonce {
        guard (payload["nonce"] as? String) == expectedNonce else {
            throw IdTokenVerifyError.nonceMismatch
        }
    }

    guard let sub = payload["sub"] as? String, !sub.isEmpty else {
        throw IdTokenVerifyError.missingClaim
    }

    return VerifiedIdToken(sub: sub, claims: payload)
}

// MARK: - Helpers

private func audienceMatches(_ aud: Any?, clientId: String) -> Bool {
    if let audStr = aud as? String { return audStr == clientId }
    if let audArr = aud as? [Any] { return audArr.contains { ($0 as? String) == clientId } }
    return false
}

/// JSONSerialization decodes JWT numeric claims as NSNumber. `Double` covers the
/// exp/iat range without loss for any realistic token lifetime.
private func numericClaim(_ value: Any?) -> TimeInterval? {
    (value as? NSNumber)?.doubleValue
}

func base64urlDecode(_ segment: String) -> Data? {
    var b64 = segment
        .replacingOccurrences(of: "-", with: "+")
        .replacingOccurrences(of: "_", with: "/")
    let remainder = b64.count % 4
    if remainder > 0 {
        b64 += String(repeating: "=", count: 4 - remainder)
    }
    return Data(base64Encoded: b64)
}

/// Build an RSA public `SecKey` from a JWK's modulus/exponent by constructing the
/// PKCS#1 `RSAPublicKey` DER (SEQUENCE { INTEGER n, INTEGER e }). SecKey with
/// `kSecAttrKeyTypeRSA` expects PKCS#1, not SubjectPublicKeyInfo.
private func rsaPublicKey(from jwk: JWK) throws -> SecKey {
    guard let modulus = base64urlDecode(jwk.n), let exponent = base64urlDecode(jwk.e) else {
        throw IdTokenVerifyError.badSignature
    }
    let der = asn1Sequence(asn1Integer(modulus) + asn1Integer(exponent))
    let attrs: [CFString: Any] = [
        kSecAttrKeyType: kSecAttrKeyTypeRSA,
        kSecAttrKeyClass: kSecAttrKeyClassPublic,
    ]
    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateWithData(der as CFData, attrs as CFDictionary, &error) else {
        throw IdTokenVerifyError.badSignature
    }
    return key
}

// MARK: - Minimal DER (ASN.1) encoding

private func asn1Length(_ length: Int) -> Data {
    if length < 0x80 { return Data([UInt8(length)]) }
    var value = length
    var bytes: [UInt8] = []
    while value > 0 {
        bytes.insert(UInt8(value & 0xff), at: 0)
        value >>= 8
    }
    return Data([UInt8(0x80 | bytes.count)] + bytes)
}

private func asn1Integer(_ bytes: Data) -> Data {
    var content = bytes
    // Strip superfluous leading zeros, but keep one byte minimum.
    while content.count > 1 && content.first == 0x00 {
        content = content.dropFirst()
    }
    // Prepend 0x00 if the high bit is set so the INTEGER stays positive.
    if let first = content.first, first & 0x80 != 0 {
        content = Data([0x00]) + content
    }
    return Data([0x02]) + asn1Length(content.count) + content
}

private func asn1Sequence(_ body: Data) -> Data {
    Data([0x30]) + asn1Length(body.count) + body
}

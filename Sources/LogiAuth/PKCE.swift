import Foundation
import CryptoKit

// PKCE (Proof Key for Code Exchange) per RFC 7636.
// Always S256 — never plain. The verifier is 32 random bytes base64url-encoded.
public enum PKCE {
    public struct Pair: Sendable, Equatable {
        public let verifier: String
        public let challenge: String
    }

    public static func generate() -> Pair {
        var bytes = [UInt8](repeating: 0, count: 32)
        // Fail-closed: a CSPRNG failure would leave `bytes` all-zero, producing a
        // predictable PKCE verifier. Never continue with weak entropy. generate()
        // is a public non-throwing API (source-stable), so we fail-fast instead of
        // adding a throws — entropy failure is unrecoverable, a valid precondition.
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            preconditionFailure("PKCE.generate: SecRandomCopyBytes failed to produce CSPRNG entropy")
        }
        let verifier = base64URL(Data(bytes))
        let challengeData = Data(SHA256.hash(data: Data(verifier.utf8)))
        return Pair(verifier: verifier, challenge: base64URL(challengeData))
    }

    private static func base64URL(_ data: Data) -> String {
        data.base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

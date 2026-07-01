import Foundation
import LogiAuth

/// Optional token persistence + refresh for LogiAuth.
///
/// The `LogiAuth` core connector deliberately does NOT store tokens — per the
/// SDK boundary ("인증만, 저장·UI는 RP 앱 기능"), where and whether a session is
/// persisted is the RP's decision. This helper is the batteries-included default
/// for RPs that DO want Keychain-backed refresh-token persistence and a
/// `refresh_token` exchange, without hand-rolling either.
///
/// Usage:
///
///     let session = try await LogiAuth.signIn()
///     let store = LogiAuthStorage(config: myConfig)
///     store.persist(session)            // save refresh_token to Keychain
///     ...
///     if store.currentRefreshToken() != nil {
///         let tokens = try await store.refresh()   // fresh access_token
///     }
///     store.signOut()                   // drop stored credential
///
/// RPs that keep tokens elsewhere (their own store, in-memory only, or on a
/// backend) should not use this type at all.
public struct LogiAuthStorage: Sendable {
    private let issuer: URL
    private let clientId: String

    private var keychain: Keychain {
        Keychain(service: "dev.1pass.LogiAuth.\(clientId)")
    }

    public init(clientId: String, issuer: URL = URL(string: "https://api.1pass.dev")!) {
        self.clientId = clientId
        self.issuer = issuer
    }

    public init(config: LogiAuthConfig) {
        self.clientId = config.clientId
        self.issuer = config.issuer
    }

    // MARK: - Persistence

    /// Persist the session's refresh_token (if any) to the Keychain. No-op when
    /// the session carries no refresh_token.
    public func persist(_ session: LogiSession) {
        if let refresh = session.refreshToken {
            keychain.set(refresh, for: Self.refreshKey)
        }
    }

    /// Synchronous read for early-launch decisions ("do we have a session?").
    public func currentRefreshToken() -> String? {
        keychain.get(Self.refreshKey)
    }

    /// Drop the stored refresh credential. Call on explicit sign-out.
    public func signOut() {
        keychain.delete(Self.refreshKey)
    }

    // MARK: - Refresh

    /// Exchange the stored refresh_token for a fresh access_token, rotating and
    /// re-persisting the refresh_token the server returns.
    /// Throws `LogiAuthError.noRefreshToken` when nothing is stored.
    @discardableResult
    public func refresh() async throws -> LogiAuthResult {
        guard let refreshToken = keychain.get(Self.refreshKey) else {
            throw LogiAuthError.noRefreshToken
        }

        var request = URLRequest(url: issuer.appendingPathComponent("oauth/token"))
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let body = [
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
            "client_id": clientId,
        ]
        request.httpBody = body
            .map { "\($0.key)=\(($0.value).addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")" }
            .joined(separator: "&")
            .data(using: .utf8)

        let (data, response) = try await URLSession.shared.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            throw LogiAuthError.tokenExchangeFailed(status: status, body: String(data: data, encoding: .utf8) ?? "")
        }
        let result = try Self.decode(data)
        if let rotated = result.refreshToken {
            keychain.set(rotated, for: Self.refreshKey)
        }
        return result
    }

    // MARK: - Internal

    private static let refreshKey = "refresh_token"

    private static func decode(_ data: Data) throws -> LogiAuthResult {
        struct TokenResponse: Decodable {
            let access_token: String
            let id_token: String?
            let refresh_token: String?
            let expires_in: Int?
            let scope: String?
            let token_type: String?
        }
        let decoded = try JSONDecoder().decode(TokenResponse.self, from: data)
        let expiresAt = decoded.expires_in.map { Date(timeIntervalSinceNow: TimeInterval($0)) }
        return LogiAuthResult(
            accessToken: decoded.access_token,
            idToken: decoded.id_token,
            refreshToken: decoded.refresh_token,
            expiresAt: expiresAt,
            scope: decoded.scope,
            tokenType: decoded.token_type ?? "Bearer"
        )
    }
}

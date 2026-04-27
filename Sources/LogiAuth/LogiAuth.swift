import Foundation
import AuthenticationServices
import UIKit

// MARK: - Public API

@MainActor
public final class LogiAuth: NSObject, ObservableObject {
    public static let shared = LogiAuth()

    @Published public private(set) var lastResult: LogiAuthResult?

    private var config: LogiAuthConfig?
    private var keychain: Keychain { Keychain(service: "dev.1pass.LogiAuth.\(config?.clientId ?? "default")") }
    private var session: ASWebAuthenticationSession?

    private override init() { super.init() }

    /// Call once at app start (e.g. in @main App's init).
    public static func configure(_ config: LogiAuthConfig) {
        Task { @MainActor in shared.config = config }
    }

    /// Drives the OAuth Authorization Code + PKCE flow.
    /// - When the logi app is installed, iOS routes the authorize URL via
    ///   Universal Links → user sees a native consent screen.
    /// - When it's not installed, the system browser (ASWebAuthenticationSession)
    ///   loads the web /oauth/authorize page.
    @discardableResult
    public static func signIn(scopes: [String]? = nil) async throws -> LogiAuthResult {
        try await shared.signIn(scopes: scopes)
    }

    public static func signOut() {
        Task { @MainActor in shared.signOutInternal() }
    }

    /// Returns a fresh access token using the stored refresh token.
    /// Throws `.noRefreshToken` if no refresh token is persisted.
    @discardableResult
    public static func refresh() async throws -> LogiAuthResult {
        try await shared.refresh()
    }

    public static func currentRefreshToken() -> String? {
        // Synchronous read for early-launch decisions.
        let cfg = MainActor.assumeIsolated { shared.config }
        guard let cfg else { return nil }
        return Keychain(service: "dev.1pass.LogiAuth.\(cfg.clientId)").get("refresh_token")
    }

    // MARK: - Implementation

    private func signIn(scopes: [String]?) async throws -> LogiAuthResult {
        guard let cfg = config else { throw LogiAuthError.notConfigured }
        let pkce = PKCE.generate()
        let state = UUID().uuidString

        var components = URLComponents(url: cfg.issuer, resolvingAgainstBaseURL: false)!
        components.path = "/oauth/authorize"
        components.queryItems = [
            .init(name: "response_type", value: "code"),
            .init(name: "client_id", value: cfg.clientId),
            .init(name: "redirect_uri", value: cfg.redirectURI.absoluteString),
            .init(name: "scope", value: (scopes ?? cfg.scopes).joined(separator: " ")),
            .init(name: "state", value: state),
            .init(name: "code_challenge", value: pkce.challenge),
            .init(name: "code_challenge_method", value: "S256")
        ]
        guard let authURL = components.url else { throw LogiAuthError.invalidAuthorizeURL }

        let callbackURL = try await beginWebAuthSession(authURL: authURL, callbackScheme: cfg.redirectURI.scheme)
        let (code, returnedState) = try parseCallback(callbackURL)
        guard returnedState == state else { throw LogiAuthError.stateMismatch }

        let result = try await exchangeCodeForToken(code: code, codeVerifier: pkce.verifier, config: cfg)
        persist(result)
        lastResult = result
        return result
    }

    private func beginWebAuthSession(authURL: URL, callbackScheme: String?) async throws -> URL {
        try await withCheckedThrowingContinuation { continuation in
            // For HTTPS Universal Link redirect URIs, callbackURLScheme should
            // be nil and we rely on the system to deliver the URL via the
            // configured callback handler (the RP app's onOpenURL or
            // ASWebAuthenticationSession). For custom schemes pass scheme.
            let scheme = (callbackScheme == "https" ? nil : callbackScheme)
            let session = ASWebAuthenticationSession(url: authURL, callbackURLScheme: scheme) { url, error in
                if let url = url {
                    continuation.resume(returning: url)
                } else if let nserr = error as NSError?,
                          nserr.domain == ASWebAuthenticationSessionError.errorDomain,
                          nserr.code == ASWebAuthenticationSessionError.canceledLogin.rawValue {
                    continuation.resume(throwing: LogiAuthError.userCancelled)
                } else {
                    continuation.resume(throwing: error ?? LogiAuthError.userCancelled)
                }
            }
            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = true
            self.session = session
            session.start()
        }
    }

    private func parseCallback(_ url: URL) throws -> (code: String, state: String) {
        guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: true),
              let items = comps.queryItems
        else { throw LogiAuthError.missingCode }
        let dict = Dictionary(uniqueKeysWithValues: items.compactMap { item -> (String, String)? in
            guard let value = item.value else { return nil }
            return (item.name, value)
        })
        if let err = dict["error"] {
            throw LogiAuthError.authorizationServerError(code: err, description: dict["error_description"])
        }
        guard let code = dict["code"], let state = dict["state"] else {
            throw LogiAuthError.missingCode
        }
        return (code, state)
    }

    private func exchangeCodeForToken(code: String, codeVerifier: String, config: LogiAuthConfig) async throws -> LogiAuthResult {
        var request = URLRequest(url: config.issuer.appendingPathComponent("oauth/token"))
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")

        let body = [
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": config.redirectURI.absoluteString,
            "client_id": config.clientId,
            "code_verifier": codeVerifier
        ]
        request.httpBody = body
            .map { "\($0.key)=\(($0.value).addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed) ?? "")" }
            .joined(separator: "&")
            .data(using: .utf8)

        let (data, response) = try await URLSession.shared.data(for: request)
        let http = (response as? HTTPURLResponse)
        let status = http?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            throw LogiAuthError.tokenExchangeFailed(status: status, body: String(data: data, encoding: .utf8) ?? "")
        }
        return try decodeTokenResponse(data)
    }

    private func decodeTokenResponse(_ data: Data) throws -> LogiAuthResult {
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

    private func refresh() async throws -> LogiAuthResult {
        guard let cfg = config else { throw LogiAuthError.notConfigured }
        guard let refreshToken = keychain.get("refresh_token") else { throw LogiAuthError.noRefreshToken }

        var request = URLRequest(url: cfg.issuer.appendingPathComponent("oauth/token"))
        request.httpMethod = "POST"
        request.setValue("application/x-www-form-urlencoded", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        let body = [
            "grant_type": "refresh_token",
            "refresh_token": refreshToken,
            "client_id": cfg.clientId
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
        let result = try decodeTokenResponse(data)
        persist(result)
        lastResult = result
        return result
    }

    private func persist(_ result: LogiAuthResult) {
        if let refresh = result.refreshToken {
            keychain.set(refresh, for: "refresh_token")
        }
    }

    private func signOutInternal() {
        keychain.delete("refresh_token")
        lastResult = nil
    }
}

// MARK: - ASWebAuthenticationSession context provider

extension LogiAuth: ASWebAuthenticationPresentationContextProviding {
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes
            .compactMap { ($0 as? UIWindowScene)?.keyWindow }
            .first ?? ASPresentationAnchor()
    }
}

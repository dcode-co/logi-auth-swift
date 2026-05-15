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

    /// Pending app-to-app handoff. Populated when signIn() opens the logi app
    /// via Universal Link; resolved when the RP forwards the callback URL via
    /// `LogiAuth.handle(_:)` from its `onOpenURL` / `onContinueUserActivity`
    /// handler. Only one handoff can be in flight at a time.
    private var pendingHandoff: PendingHandoff?

    /// Default deadline for the user to complete approval in the logi app
    /// before signIn() throws .handoffTimeout. Five minutes covers slow Face
    /// ID retries + push approval but bounds the continuation lifetime.
    private static let handoffTimeout: Duration = .seconds(300)

    private struct PendingHandoff {
        let state: String
        let continuation: CheckedContinuation<URL, Error>
        let timeoutTask: Task<Void, Never>
    }

    private override init() { super.init() }

    /// Call once at app start (e.g. in @main App's init).
    public static func configure(_ config: LogiAuthConfig) {
        Task { @MainActor in shared.config = config }
    }

    /// Drives the OAuth Authorization Code + PKCE flow with app-to-app handoff
    /// preferred. Two-stage:
    ///
    ///   1. `UIApplication.open(authorizeURL, options: [.universalLinksOnly: true])`.
    ///      If the logi app is installed and its associated-domain entitlement
    ///      claims `api.1pass.dev`, iOS launches it directly (no browser).
    ///      The logi app processes consent natively, then opens the RP's
    ///      `redirect_uri` with `?code=…&state=…`. The RP must call
    ///      `LogiAuth.handle(_:)` from its `onOpenURL` /
    ///      `onContinueUserActivity` handler to forward that URL into the SDK.
    ///   2. If the system reports no associated app (universalLinksOnly returns
    ///      false), fall back to `ASWebAuthenticationSession` loading the web
    ///      `/oauth/authorize` page; the callback closes back into the SDK.
    ///
    /// Why try app-to-app first? Apple suppresses Universal Link handoff
    /// inside ASWebAuthenticationSession, so the only way to reach the native
    /// app is to call `UIApplication.open` BEFORE opening any auth session.
    @discardableResult
    public static func signIn(scopes: [String]? = nil) async throws -> LogiAuthResult {
        try await shared.signIn(scopes: scopes)
    }

    /// Forward a URL received via the RP's `onOpenURL` /
    /// `onContinueUserActivity` handler back into the SDK. Returns `true` when
    /// the URL matched a pending sign-in handoff (it was consumed); `false`
    /// when no handoff is in flight (the RP should handle the URL itself).
    ///
    /// Call sites on the RP app:
    ///
    ///     .onOpenURL { url in
    ///         _ = LogiAuth.handle(url)
    ///     }
    ///     .onContinueUserActivity(NSUserActivityTypeBrowsingWeb) { activity in
    ///         if let url = activity.webpageURL { _ = LogiAuth.handle(url) }
    ///     }
    @discardableResult
    public static func handle(_ url: URL) -> Bool {
        shared.handleCallback(url)
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
        guard pendingHandoff == nil else { throw LogiAuthError.alreadyInProgress }

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

        let callbackURL = try await acquireCallback(authURL: authURL, state: state, callbackScheme: cfg.redirectURI.scheme)
        let (code, returnedState) = try parseCallback(callbackURL)
        guard returnedState == state else { throw LogiAuthError.stateMismatch }

        let result = try await exchangeCodeForToken(code: code, codeVerifier: pkce.verifier, config: cfg)
        persist(result)
        lastResult = result
        return result
    }

    /// Try app-to-app handoff first (preferred — works even when the RP would
    /// otherwise wrap the IdP in ASWebAuthenticationSession). On failure
    /// (`universalLinksOnly` returned false → no associated app installed),
    /// fall back to ASWAS loading the web /oauth/authorize page.
    private func acquireCallback(authURL: URL, state: String, callbackScheme: String?) async throws -> URL {
        if await tryNativeHandoff(authURL: authURL) {
            return try await waitForExternalCallback(state: state)
        }
        return try await beginWebAuthSession(authURL: authURL, callbackScheme: callbackScheme)
    }

    private func tryNativeHandoff(authURL: URL) async -> Bool {
        await withCheckedContinuation { cont in
            UIApplication.shared.open(authURL, options: [.universalLinksOnly: true]) { ok in
                cont.resume(returning: ok)
            }
        }
    }

    /// Suspend until the RP forwards the redirect_uri callback via
    /// `LogiAuth.handle(_:)`, or the deadline fires (.handoffTimeout).
    /// `pendingHandoff` is cleared in both branches by the resolver.
    private func waitForExternalCallback(state: String) async throws -> URL {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<URL, Error>) in
            let timeout = Task { [weak self] in
                try? await Task.sleep(for: Self.handoffTimeout)
                guard !Task.isCancelled else { return }
                await self?.failPendingHandoff(.handoffTimeout)
            }
            self.pendingHandoff = PendingHandoff(state: state, continuation: continuation, timeoutTask: timeout)
        }
    }

    private func failPendingHandoff(_ error: LogiAuthError) {
        guard let pending = pendingHandoff else { return }
        pendingHandoff = nil
        pending.timeoutTask.cancel()
        pending.continuation.resume(throwing: error)
    }

    /// Resolve the pending handoff with the URL the RP received via onOpenURL
    /// (or onContinueUserActivity for HTTPS redirect URIs). Returns whether
    /// the URL was consumed so the RP can choose to handle non-LogiAuth URLs
    /// itself.
    ///
    /// We must validate the URL matches the configured `redirect_uri` before
    /// consuming. Without this check, an unrelated universal link delivered
    /// while a sign-in is pending (e.g. an `applinks:` host the RP also owns)
    /// would be force-fed to the OAuth parser and throw `.missingCode` —
    /// confusing the user with a fake "OAuth failed" error when in fact no
    /// callback was received yet. Reported by ainote 2026-05-15.
    fileprivate func handleCallback(_ url: URL) -> Bool {
        guard let pending = pendingHandoff else { return false }
        guard let cfg = config, urlMatchesRedirect(url, redirect: cfg.redirectURI) else {
            // Not our callback — leave the pending handoff alive so the real
            // callback (or the timeout) can resolve it.
            return false
        }
        pendingHandoff = nil
        pending.timeoutTask.cancel()
        pending.continuation.resume(returning: url)
        return true
    }

    /// Match callback URL against the configured redirect URI by scheme + host
    /// + path. Query string is intentionally not compared (it carries the
    /// `code`/`state`/`error` we want to forward upstream).
    private func urlMatchesRedirect(_ url: URL, redirect: URL) -> Bool {
        guard
            let urlScheme = url.scheme?.lowercased(),
            let redirectScheme = redirect.scheme?.lowercased(),
            urlScheme == redirectScheme
        else { return false }
        // Custom schemes (ainote://, easybracket://...) usually carry the
        // path inside the host/path combo; we compare both case-insensitively
        // to tolerate iOS lowercasing the host.
        let urlHost = url.host?.lowercased() ?? ""
        let redirectHost = redirect.host?.lowercased() ?? ""
        guard urlHost == redirectHost else { return false }
        return url.path == redirect.path
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

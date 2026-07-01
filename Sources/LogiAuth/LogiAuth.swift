import Foundation
import Security
import AuthenticationServices
import UIKit

// MARK: - Public API

@MainActor
public final class LogiAuth: NSObject, ObservableObject {
    public static let shared = LogiAuth()

    @Published public private(set) var lastSession: LogiSession?

    private var config: LogiAuthConfig?
    private var session: ASWebAuthenticationSession?

    /// In-memory JWKS cache. The IdP rotates signing keys rarely; caching for
    /// one hour avoids a network round-trip on every sign-in while still
    /// picking up rotations on the next window. Keyed by issuer URL.
    private var jwksCache: (issuer: URL, jwks: JWKS, fetchedAt: Date)?
    private static let jwksTTL: TimeInterval = 3600

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
    public static func signIn(scopes: [String]? = nil) async throws -> LogiSession {
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

    // Token persistence, refresh(), signOut(), and anonymous-device bootstrap
    // are NOT part of the auth core — they live in the optional `LogiAuthStorage`
    // product. The core connector only proves identity; where/whether tokens are
    // stored is the RP app's concern. See LogiAuthStorage.

    // MARK: - Implementation

    private func signIn(scopes: [String]?) async throws -> LogiSession {
        guard let cfg = config else { throw LogiAuthError.notConfigured }
        guard pendingHandoff == nil else { throw LogiAuthError.alreadyInProgress }

        let pkce = PKCE.generate()
        let state = UUID().uuidString
        // nonce is always generated and always verified — it binds the id_token
        // to this specific authorize request (replay defense). Server echoes it
        // through authorize → grant → id_token (id_token_issuer.rb).
        let nonce = Self.randomURLToken()

        var components = URLComponents(url: cfg.issuer, resolvingAgainstBaseURL: false)!
        components.path = "/oauth/authorize"
        components.queryItems = [
            .init(name: "response_type", value: "code"),
            .init(name: "client_id", value: cfg.clientId),
            .init(name: "redirect_uri", value: cfg.redirectURI.absoluteString),
            .init(name: "scope", value: (scopes ?? cfg.scopes).joined(separator: " ")),
            .init(name: "state", value: state),
            .init(name: "nonce", value: nonce),
            .init(name: "code_challenge", value: pkce.challenge),
            .init(name: "code_challenge_method", value: "S256")
        ]
        guard let authURL = components.url else { throw LogiAuthError.invalidAuthorizeURL }

        let callbackURL = try await acquireCallback(authURL: authURL, state: state, callbackScheme: cfg.redirectURI.scheme)
        let (code, returnedState) = try parseCallback(callbackURL)
        guard returnedState == state else { throw LogiAuthError.stateMismatch }

        let tokens = try await exchangeCodeForToken(code: code, codeVerifier: pkce.verifier, config: cfg)

        // Verify the id_token (public-client trust boundary). This is the sole
        // new safety contract of v1.0 — without it `sub` would be unverified.
        guard let idToken = tokens.idToken else { throw LogiAuthError.missingIdToken }
        let jwks = try await fetchJWKS(issuer: cfg.issuer)
        let verified: VerifiedIdToken
        do {
            verified = try verifyIdToken(
                idToken,
                jwks: jwks,
                expected: .init(issuer: cfg.tokenIssuer, clientId: cfg.clientId, nonce: nonce)
            )
        } catch let error as IdTokenVerifyError {
            throw LogiAuthError.idTokenInvalid(code: error.code)
        }

        let session = LogiSession(
            sub: verified.sub,
            email: verified.claims["email"] as? String,
            idToken: idToken,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            expiresAt: tokens.expiresAt,
            scope: tokens.scope,
            tokenType: tokens.tokenType
        )
        lastSession = session
        return session
    }

    /// Fetch the IdP's JWKS for id_token signature verification, cached for
    /// `jwksTTL`. On a `kid` rotation the first verification within the window
    /// would fail `unknown_kid`; the RP can retry, which re-fetches after TTL.
    private func fetchJWKS(issuer: URL) async throws -> JWKS {
        if let cached = jwksCache,
           cached.issuer == issuer,
           Date().timeIntervalSince(cached.fetchedAt) < Self.jwksTTL {
            return cached.jwks
        }
        let base = issuer.absoluteString.hasSuffix("/")
            ? String(issuer.absoluteString.dropLast())
            : issuer.absoluteString
        guard let url = URL(string: base + "/.well-known/jwks.json") else {
            throw LogiAuthError.jwksFetchFailed(status: 0)
        }
        let (data, response) = try await URLSession.shared.data(from: url)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0
        guard (200..<300).contains(status) else {
            throw LogiAuthError.jwksFetchFailed(status: status)
        }
        let jwks = try JSONDecoder().decode(JWKS.self, from: data)
        jwksCache = (issuer, jwks, Date())
        return jwks
    }

    /// 32 random bytes, base64url — same shape as the PKCE verifier. Used for
    /// the OIDC nonce.
    private static func randomURLToken() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        _ = SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes)
        return Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Try app-to-app handoff first (preferred — works even when the RP would
    /// otherwise wrap the IdP in ASWebAuthenticationSession). On failure
    /// (`universalLinksOnly` returned false → no associated app installed),
    /// fall back to ASWAS loading the web /oauth/authorize page.
    private func acquireCallback(authURL: URL, state: String, callbackScheme: String?) async throws -> URL {
        if await tryNativeHandoff(authURL: authURL) {
            return try await waitForExternalCallback(state: state)
        }
        return try await beginWebAuthSession(authURL: authURL, callbackScheme: callbackScheme, state: state)
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
        // HTTPS-fallback path keeps the ASWAS UI on screen until the RP
        // delivers the callback URL. Dismiss it now so the user isn't left
        // staring at the auth page after redirecting back to the app.
        session?.cancel()
        session = nil
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

    private func beginWebAuthSession(authURL: URL, callbackScheme: String?, state: String) async throws -> URL {
        // HTTPS Universal Link redirect URI: ASWAS cannot intercept the
        // callback (Apple suppresses URL handoff inside ASWAS), so its
        // completion handler will never fire with a URL. The system delivers
        // the redirect via the RP app's onContinueUserActivity →
        // LogiAuth.handle(_:). We set up pendingHandoff to await that, and
        // start ASWAS only to render the /oauth/authorize page. ASWAS
        // completion still fires on user cancel — we map that to
        // .userCancelled by failing the handoff. (Pre-fix: continuation
        // never resumed → signIn() hung forever for HTTPS-redirect RPs.)
        if callbackScheme == "https" {
            return try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<URL, Error>) in
                let timeout = Task { [weak self] in
                    try? await Task.sleep(for: Self.handoffTimeout)
                    guard !Task.isCancelled else { return }
                    await self?.failPendingHandoff(.handoffTimeout)
                }
                self.pendingHandoff = PendingHandoff(state: state, continuation: continuation, timeoutTask: timeout)

                let session = ASWebAuthenticationSession(url: authURL, callbackURLScheme: nil) { [weak self] _, error in
                    guard let nserr = error as NSError?,
                          nserr.domain == ASWebAuthenticationSessionError.errorDomain,
                          nserr.code == ASWebAuthenticationSessionError.canceledLogin.rawValue
                    else { return }
                    Task { @MainActor in self?.failPendingHandoff(.userCancelled) }
                }
                session.presentationContextProvider = self
                session.prefersEphemeralWebBrowserSession = true
                self.session = session
                session.start()
            }
        }

        return try await withCheckedThrowingContinuation { continuation in
            // Custom scheme — ASWAS receives callback URL directly.
            let session = ASWebAuthenticationSession(url: authURL, callbackURLScheme: callbackScheme) { url, error in
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
}

// MARK: - ASWebAuthenticationSession context provider

extension LogiAuth: ASWebAuthenticationPresentationContextProviding {
    public func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        UIApplication.shared.connectedScenes
            .compactMap { ($0 as? UIWindowScene)?.keyWindow }
            .first ?? ASPresentationAnchor()
    }
}

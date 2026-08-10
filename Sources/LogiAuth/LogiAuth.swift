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

    /// Which route the in-flight signIn() took, or nil when none is running.
    /// Deliberately NOT stored on `PendingHandoff`: the custom-scheme web route
    /// (`beginWebAuthSession`, callbackScheme != "https") never populates
    /// `pendingHandoff` — its ASWAS completion handler owns the continuation
    /// directly — so a flag living there would read `nil` on that route and the
    /// RP would mistake an in-flight web sign-in for no sign-in at all.
    private var activeHandoffKind: LogiHandoffKind?

    /// Monotonic id of the newest signIn(). Late cleanup hops must only tear
    /// down state their own flow still owns — see the `defer` in `signIn`.
    private var handoffGeneration: UInt64 = 0

    /// True for the whole duration of a signIn(), across every route. Backs
    /// the `.alreadyInProgress` guard; `pendingHandoff` cannot, because the
    /// custom-scheme route never sets it.
    ///
    /// `internal` (not `private`) so the serialization regression test can read
    /// it; not part of the public SDK surface.
    private(set) var signInInFlight = false

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

    /// Verify the id_token returned by `LogiAuthStorage.refresh()` and promote it
    /// to a verified `LogiSession`. The core connector owns the JWKS cache, so
    /// verification of a refreshed token must go through here — `refresh()` alone
    /// returns an UNVERIFIED `LogiAuthResult`, and trusting its `sub`/`email`
    /// directly would reopen the same signature gap `signIn` closes. The refresh
    /// response carries no nonce, so nonce is not checked; `at_hash` still binds
    /// when the token carries one. Additive: `signIn`'s contract is unchanged.
    @discardableResult
    public static func verify(_ result: LogiAuthResult) async throws -> LogiSession {
        try await shared.verify(result)
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

    /// Which route the in-flight `signIn()` took, or `nil` when no sign-in is
    /// running. Read this before deciding to `cancel()` — the two routes need
    /// opposite handling on foreground-return. See `LogiHandoffKind`.
    ///
    ///     if LogiAuth.handoffKind == .native { LogiAuth.cancel() }
    ///
    /// Cancelling unconditionally would kill a live `.web` sign-in whose sheet
    /// is still on screen.
    public static var handoffKind: LogiHandoffKind? { shared.activeHandoffKind }

    /// Cancel an in-flight `signIn()`, resolving it with
    /// `LogiAuthError.userCancelled`.
    ///
    /// This is the only way out of a `.native` app-to-app handoff that the user
    /// abandoned. iOS reports nothing when someone returns from the logi app
    /// without approving, so `signIn()` would otherwise stay suspended until
    /// the 5-minute `.handoffTimeout` — and every `signIn()` in between throws
    /// `.alreadyInProgress`. Detecting the return is the RP's job (scene phase);
    /// this hands the verdict to the SDK. Gate it on
    /// `handoffKind == .native` — see `handoffKind`.
    ///
    /// Returns whether a sign-in was actually cancelled. `false` means the
    /// callback had already landed or nothing was in flight, which is safe to
    /// ignore — a cancel racing a callback loses, and the sign-in completes.
    @discardableResult
    public static func cancel() -> Bool {
        shared.cancelPending()
    }

    // Token persistence, refresh(), signOut(), and anonymous-device bootstrap
    // are NOT part of the auth core — they live in the optional `LogiAuthStorage`
    // product. The core connector only proves identity; where/whether tokens are
    // stored is the RP app's concern. See LogiAuthStorage.

    // MARK: - Implementation

    private func signIn(scopes: [String]?) async throws -> LogiSession {
        guard let cfg = config else { throw LogiAuthError.notConfigured }
        // Serialize on the whole call, not on `pendingHandoff`. That property
        // is only populated by the native and HTTPS routes — the custom-scheme
        // route keeps its continuation inside the ASWAS completion handler and
        // leaves it nil. Guarding on it therefore let two custom-scheme
        // sign-ins run at once over a single `session` slot: the second
        // overwrote the first, stranding the first continuation forever and
        // pointing cancel() at the wrong flow. `.alreadyInProgress` already
        // documents this intent ("Concurrent flows would race for the same
        // continuation"); the old guard just under-enforced it.
        guard !signInInFlight else { throw LogiAuthError.alreadyInProgress }
        signInInFlight = true
        // Clear shared state on exit — success, throw, or cancel. Leaving the
        // route set would make `handoffKind` report a finished sign-in, and an
        // RP gating cancel() on it would cancel the NEXT one.
        //
        // Generation-scoped even though sign-ins are now serialized: the
        // custom-scheme cleanup hop is queued onto the MainActor and can land
        // after THIS call returns and the next one has started.
        handoffGeneration &+= 1
        let generation = handoffGeneration
        defer {
            signInInFlight = false
            // `return` is illegal inside defer — plain `if`, not `guard`.
            if handoffGeneration == generation {
                activeHandoffKind = nil
                // Custom-scheme ASWAS keeps `session` set past its callback;
                // drop it here so a later cancel() doesn't mistake a finished
                // sign-in for a live one.
                session = nil
            }
        }

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

        // Verify the id_token (public-client trust boundary) and assemble the
        // verified session. Shared with verify(_:) via makeVerifiedSession so the
        // JWKS cache + key-rotation refetch behave identically on both paths.
        guard let idToken = tokens.idToken else { throw LogiAuthError.missingIdToken }
        return try await makeVerifiedSession(
            idToken: idToken,
            accessToken: tokens.accessToken,
            refreshToken: tokens.refreshToken,
            expiresAt: tokens.expiresAt,
            scope: tokens.scope,
            tokenType: tokens.tokenType,
            nonce: nonce,
            cfg: cfg
        )
    }

    /// Instance impl for `verify(_:)`. See the static overload's docs. The
    /// refresh response carries no nonce, so `nonce == nil` (nonce binds the
    /// original authorize request, which a refresh has none of).
    private func verify(_ result: LogiAuthResult) async throws -> LogiSession {
        guard let cfg = config else { throw LogiAuthError.notConfigured }
        guard let idToken = result.idToken else { throw LogiAuthError.missingIdToken }
        return try await makeVerifiedSession(
            idToken: idToken,
            accessToken: result.accessToken,
            refreshToken: result.refreshToken,
            expiresAt: result.expiresAt,
            scope: result.scope,
            tokenType: result.tokenType,
            nonce: nil,
            cfg: cfg
        )
    }

    /// Verify an id_token and assemble a `LogiSession`. Shared by `signIn`
    /// (nonce-bound) and `verify(_:)` (refresh path, `nonce == nil`). Busts and
    /// refetches the JWKS exactly once on `unknown_kid` (key rotation) so a
    /// stale cache never turns a rotation into an hour-long outage.
    private func makeVerifiedSession(
        idToken: String,
        accessToken: String,
        refreshToken: String?,
        expiresAt: Date?,
        scope: String?,
        tokenType: String,
        nonce: String?,
        cfg: LogiAuthConfig
    ) async throws -> LogiSession {
        let expected = VerifyExpected(issuer: cfg.tokenIssuer, clientId: cfg.clientId, nonce: nonce)
        let (jwks, fromCache) = try await fetchJWKS(issuer: cfg.issuer)
        let verified: VerifiedIdToken
        do {
            verified = try verifyIdToken(idToken, jwks: jwks, expected: expected, accessToken: accessToken)
        } catch IdTokenVerifyError.unknownKid where fromCache {
            // The IdP rotated signing keys while our JWKS cache was still within
            // its TTL. A stale cache must not turn normal key rotation into an
            // hour-long auth outage — bust it, refetch once, and re-verify.
            do {
                let (freshJwks, _) = try await fetchJWKS(issuer: cfg.issuer, forceRefresh: true)
                verified = try verifyIdToken(idToken, jwks: freshJwks, expected: expected, accessToken: accessToken)
            } catch let error as IdTokenVerifyError {
                throw LogiAuthError.idTokenInvalid(code: error.code)
            }
        } catch let error as IdTokenVerifyError {
            throw LogiAuthError.idTokenInvalid(code: error.code)
        }

        let session = LogiSession(
            sub: verified.sub,
            email: verified.claims["email"] as? String,
            idToken: idToken,
            accessToken: accessToken,
            refreshToken: refreshToken,
            expiresAt: expiresAt,
            scope: scope,
            tokenType: tokenType
        )
        lastSession = session
        return session
    }

    /// Fetch the IdP's JWKS for id_token signature verification, cached for
    /// `jwksTTL`. Returns whether the result came from the cache so the caller
    /// can bust + refetch once on an `unknown_kid` (key rotation) rather than
    /// failing sign-ins for the rest of the TTL window.
    /// Pass `forceRefresh: true` to skip the cache and re-fetch.
    private func fetchJWKS(issuer: URL, forceRefresh: Bool = false) async throws -> (jwks: JWKS, fromCache: Bool) {
        if !forceRefresh,
           let cached = jwksCache,
           cached.issuer == issuer,
           Date().timeIntervalSince(cached.fetchedAt) < Self.jwksTTL {
            return (cached.jwks, true)
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
        return (jwks, false)
    }

    /// 32 random bytes, base64url — same shape as the PKCE verifier. Used for
    /// the OIDC nonce.
    private static func randomURLToken() -> String {
        var bytes = [UInt8](repeating: 0, count: 32)
        // Fail-closed: a CSPRNG failure would leave `bytes` all-zero, yielding a
        // predictable nonce (replay-defense bypass). Entropy failure is
        // unrecoverable, so we fail-fast rather than proceeding with weak bytes.
        guard SecRandomCopyBytes(kSecRandomDefault, bytes.count, &bytes) == errSecSuccess else {
            preconditionFailure("randomURLToken: SecRandomCopyBytes failed to produce CSPRNG entropy")
        }
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
            activeHandoffKind = .native
            return try await waitForExternalCallback(state: state)
        }
        activeHandoffKind = .web
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

    /// Drop the finished ASWAS session, but only while the sign-in that opened
    /// it is still the current one. A late cleanup hop from a previous flow
    /// must not clear a newer flow's session.
    private func releaseSession(ifGeneration generation: UInt64) {
        guard handoffGeneration == generation else { return }
        session = nil
    }

    /// Instance impl for `cancel()`. Covers all three suspension shapes:
    ///
    ///   - `.native` handoff — `pendingHandoff` holds the continuation;
    ///     `failPendingHandoff` resolves it.
    ///   - `.web` HTTPS route — BOTH `pendingHandoff` and `session` are live.
    ///   - `.web` custom-scheme route — no `pendingHandoff`; the ASWAS
    ///     completion handler owns the continuation, and `session.cancel()`
    ///     wakes it with `canceledLogin` → `.userCancelled`.
    ///
    /// Order matters: consume `pendingHandoff` BEFORE cancelling the session,
    /// so the ASWAS completion handler's own `failPendingHandoff(.userCancelled)`
    /// finds nothing and no-ops. Resuming a continuation twice traps.
    /// `handleCallback` (:313) uses the same order for the same reason.
    private func cancelPending() -> Bool {
        guard pendingHandoff != nil || session != nil else { return false }
        failPendingHandoff(.userCancelled)
        // Hold a local strong reference across cancel(): clearing `session`
        // first must not deallocate the session before it delivers the
        // completion callback the custom-scheme route depends on.
        let active = session
        session = nil
        active?.cancel()
        return true
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
            // Capture the generation by value — an ASWAS reference captured in
            // its own completion handler would retain a cycle.
            let generation = handoffGeneration
            let session = ASWebAuthenticationSession(url: authURL, callbackURLScheme: callbackScheme) { [weak self] url, error in
                // This route resolves its continuation here rather than through
                // `pendingHandoff`, so nothing else drops `session`. Release it
                // now: a stale reference makes `cancel()` report `true` for a
                // sign-in that already finished. Generation-scoped because this
                // hop is queued onto the MainActor — by the time it runs, a
                // second signIn() may already have stored ITS session, and
                // clearing that one would leave the new flow uncancellable.
                Task { @MainActor in self?.releaseSession(ifGeneration: generation) }
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

    // `internal` (not `private`) so the duplicate-key regression test can drive
    // the real parser; not part of the public SDK surface.
    func parseCallback(_ url: URL) throws -> (code: String, state: String) {
        guard let comps = URLComponents(url: url, resolvingAgainstBaseURL: true),
              let items = comps.queryItems
        else { throw LogiAuthError.missingCode }
        // OAuth callback params should be unique; a duplicate key (malformed or
        // hostile callback) must not crash the app. RFC 6749 leaves duplicates
        // undefined, so we take first-wins and drop the rest instead of
        // `Dictionary(uniqueKeysWithValues:)`, which traps on a repeated key.
        let dict = Dictionary(
            items.compactMap { item -> (String, String)? in
                guard let value = item.value else { return nil }
                return (item.name, value)
            },
            uniquingKeysWith: { first, _ in first }
        )
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

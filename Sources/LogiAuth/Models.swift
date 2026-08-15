import Foundation

public struct LogiAuthConfig: Sendable {
    public let clientId: String
    /// Redirect URI registered with the logi IdP. Recommended: a claimed HTTPS
    /// URL on your RP domain (Universal Link) so the IdP app can hand the
    /// authorization code back to your app via /.well-known/apple-app-site-association.
    /// Falls back to a custom-scheme URI if you cannot register a domain.
    public let redirectURI: URL
    public let issuer: URL
    /// Expected `iss` claim inside the id_token. In production this is the
    /// canonical issuer URL `https://api.1pass.dev` (published via OIDC
    /// discovery and asserted by the server) — the URL is the source of truth.
    /// The bare string `"logi"` is a dev-only fallback and must NOT be used
    /// against production tokens. Only override for a non-standard deployment.
    public let tokenIssuer: String
    public let scopes: [String]
    /// Host that receives the **native app-to-app handoff** leg of `signIn()`,
    /// and only that leg. `nil` (the default) means derive it — see
    /// `resolvedNativeAuthorizeHost`.
    ///
    /// This exists because the two legs of `signIn()` need different hosts.
    /// `api.1pass.dev` claims `/oauth/authorize*` in its AASA so the logi app
    /// can be launched app-to-app — but that claim also intercepts the
    /// **browser** OAuth flow of web RPs, dropping the user into the logi app
    /// mid-login and returning the callback to the wrong browser. Splitting the
    /// hosts keeps the claim (native leg → `open.1pass.dev`) while leaving the
    /// web fallback on an unclaimed host (`api.1pass.dev`).
    ///
    /// 🔴 This is NOT `issuer`. `issuer` still addresses token exchange, JWKS,
    /// revoke, and the `LogiAuthStorage` endpoints; moving it would break the
    /// token exchange and every sign-in with it. Only the authorize handoff URL
    /// is affected.
    public let nativeAuthorizeHost: String?
    /// The stock production issuer. Also the discriminator for automatic
    /// handoff-host derivation — see `resolvedNativeAuthorizeHost`.
    public static let defaultIssuer = URL(string: "https://api.1pass.dev")!
    /// The bouncer host that keeps the `/oauth/authorize*` Universal Link claim.
    public static let defaultNativeAuthorizeHost = "open.1pass.dev"

    /// The host the native handoff URL is actually built with — the single
    /// definition both `signIn()` and its tests read.
    ///
    /// - An explicit non-empty `nativeAuthorizeHost` always wins.
    /// - Otherwise, the split applies **only to the stock production issuer**.
    ///   A staging or self-hosted deployment gets `issuer.host` back, i.e. the
    ///   pre-1.3.0 behaviour of one host for both legs.
    ///
    /// Deriving unconditionally would be wrong: `open.1pass.dev` is a
    /// production host, and pointing a staging RP's handoff at it would send
    /// the authorize request to the wrong deployment. The SDK cannot know which
    /// host a custom deployment claims, so it declines to guess and asks the RP
    /// to say so with `nativeAuthorizeHost`.
    public var resolvedNativeAuthorizeHost: String? {
        if let explicit = nativeAuthorizeHost, !explicit.isEmpty { return explicit }
        guard issuer.host?.lowercased() == Self.defaultIssuer.host else { return issuer.host }
        return Self.defaultNativeAuthorizeHost
    }

    public init(
        clientId: String,
        redirectURI: URL,
        issuer: URL = LogiAuthConfig.defaultIssuer,
        tokenIssuer: String = "https://api.1pass.dev",
        scopes: [String] = ["openid", "profile:basic", "email"],
        nativeAuthorizeHost: String? = nil
    ) {
        self.clientId = clientId
        self.redirectURI = redirectURI
        self.issuer = issuer
        self.tokenIssuer = tokenIssuer
        self.scopes = scopes
        self.nativeAuthorizeHost = nativeAuthorizeHost
    }
}

/// The verified outcome of a successful `signIn()`. `sub` is populated only
/// after this SDK has verified the id_token's RS256 signature and claims — it
/// is the sole new safety contract of v1.0. Identical shape across all 4 SDKs.
public struct LogiSession: Sendable, Equatable {
    /// Verified subject from the id_token — pairwise per client.
    public let sub: String
    /// `email` claim, if present and the scope was granted.
    public let email: String?
    /// Raw id_token (already verified by this SDK).
    public let idToken: String
    public let accessToken: String
    public let refreshToken: String?
    public let expiresAt: Date?
    public let scope: String?
    public let tokenType: String

    public init(
        sub: String,
        email: String? = nil,
        idToken: String,
        accessToken: String,
        refreshToken: String? = nil,
        expiresAt: Date? = nil,
        scope: String? = nil,
        tokenType: String = "Bearer"
    ) {
        self.sub = sub
        self.email = email
        self.idToken = idToken
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.expiresAt = expiresAt
        self.scope = scope
        self.tokenType = tokenType
    }
}

public struct LogiAuthResult: Sendable, Equatable {
    public let accessToken: String
    public let idToken: String?
    public let refreshToken: String?
    public let expiresAt: Date?
    public let scope: String?
    public let tokenType: String

    public init(
        accessToken: String,
        idToken: String? = nil,
        refreshToken: String? = nil,
        expiresAt: Date? = nil,
        scope: String? = nil,
        tokenType: String = "Bearer"
    ) {
        self.accessToken = accessToken
        self.idToken = idToken
        self.refreshToken = refreshToken
        self.expiresAt = expiresAt
        self.scope = scope
        self.tokenType = tokenType
    }
}

/// Which route the in-flight `signIn()` took. Exposed via
/// `LogiAuth.handoffKind` so the RP can tell the two apart — they need
/// opposite handling when the user leaves the app.
///
/// `.native` means iOS launched the logi app and the SDK is suspended waiting
/// for the RP to forward the callback. The system gives no signal when the
/// user comes back without approving, so an RP that detects the return must
/// call `LogiAuth.cancel()` itself.
///
/// `.web` means an ASWebAuthenticationSession is on screen. The system already
/// reports dismissal as `.userCancelled`, and leaving the app (home, app
/// switcher) does NOT mean the user abandoned the flow — the sheet is still
/// there on return. An RP that cancels on foreground-return would kill a live
/// web sign-in, so it must check this before acting.
public enum LogiHandoffKind: String, Sendable, Equatable {
    case native
    case web
}

/// What `LogiAuth.authorize(startURL:)` hands back: the two values the
/// authorization server put on the redirect, and nothing else.
///
/// Deliberately does NOT carry tokens or the PKCE verifier. In the backend-led
/// (BFF) flow those live only on the RP's server — the app never sees them, so
/// a compromised app cannot leak them. The RP forwards `code` and `state` to
/// its own backend along with the `txn_id` it got from `/start`, and the
/// backend does the token exchange with `client_secret` + `code_verifier`.
///
/// `state` is echoed back for the RP to pass along; it is **not** a credential.
/// The backend authenticates the completion request by its own transaction
/// record, not by this value.
public struct LogiCallback: Sendable, Equatable {
    public let code: String
    public let state: String

    public init(code: String, state: String) {
        self.code = code
        self.state = state
    }
}

// `Equatable` is additive (all payloads are String/Int) — tests and RP retry
// logic compare verdicts by value instead of reflecting on the description.
public enum LogiAuthError: LocalizedError, Sendable, Equatable {
    case notConfigured
    case invalidAuthorizeURL
    /// `authorize(startURL:)` was handed a URL with no `state` query item. The
    /// RP's backend must put one there — without it the SDK cannot tell the
    /// callback for this flow apart from a stale or injected one.
    case missingStateInStartURL
    /// `authorize(startURL:nativeStartURL:)` was handed a pair that is not the
    /// same authorization request: the query or path differs beyond the host,
    /// or a URL carries a duplicated `state`. The two URLs must be one request
    /// on different hosts — a drifting `state` makes the fallback a different
    /// transaction than the one the callback is matched against, a drifting
    /// `redirect_uri` strands the handoff until timeout, and drifting PKCE
    /// fails the backend exchange after the user already authenticated.
    /// Launch-time input validation — nothing has been opened when this is
    /// thrown.
    case startURLPairMismatch
    case userCancelled
    case stateMismatch
    case missingCode
    case authorizationServerError(code: String, description: String?)
    case tokenExchangeFailed(status: Int, body: String)
    case noRefreshToken
    /// Native app handoff started but no callback arrived within the deadline
    /// (default 5 min). User likely dismissed the logi app without approving.
    case handoffTimeout
    /// signIn() called while a previous signIn() was still awaiting a callback.
    /// Concurrent flows would race for the same continuation.
    case alreadyInProgress
    /// Token response had no id_token — was `openid` in the requested scopes?
    case missingIdToken
    /// id_token RS256 signature or claim verification failed. `code` mirrors
    /// the golden-vector error string (e.g. "bad_signature", "aud_mismatch").
    case idTokenInvalid(code: String)
    /// Could not fetch the IdP's JWKS for id_token verification.
    case jwksFetchFailed(status: Int)
    /// `ASWebAuthenticationSession.start()` refused to open — no authorization
    /// page was ever shown. Usually a missing presentation context or a call
    /// from a detached/backgrounded scene.
    case webAuthSessionStartFailed

    public var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "LogiAuth.configure(_:) 가 호출되지 않았습니다."
        case .invalidAuthorizeURL:
            return "/oauth/authorize URL을 만들 수 없습니다."
        case .missingStateInStartURL:
            return "authorize(startURL:) 에 넘긴 URL에 state 파라미터가 없습니다."
        case .startURLPairMismatch:
            return "startURL 과 nativeStartURL 이 같은 인가 요청이 아닙니다 — 호스트만 달라야 합니다."
        case .userCancelled:
            return "사용자가 로그인을 취소했습니다."
        case .stateMismatch:
            return "state 파라미터가 일치하지 않습니다 (CSRF 의심)."
        case .missingCode:
            return "인증 코드가 누락되었습니다."
        case .authorizationServerError(let code, let desc):
            return "logi 인증 서버 오류: \(code) — \(desc ?? "")"
        case .tokenExchangeFailed(let status, let body):
            return "토큰 교환 실패 (\(status)): \(body)"
        case .noRefreshToken:
            return "refresh token 이 저장되어 있지 않습니다."
        case .handoffTimeout:
            return "logi 앱에서 응답이 오지 않았습니다 (시간 초과)."
        case .alreadyInProgress:
            return "이미 진행 중인 로그인이 있습니다."
        case .missingIdToken:
            return "id_token 이 응답에 없습니다 (scope 에 openid 가 있었나요?)."
        case .idTokenInvalid(let code):
            return "id_token 검증 실패 (\(code))."
        case .webAuthSessionStartFailed:
            return "인증 세션을 열 수 없습니다."
        case .jwksFetchFailed(let status):
            return "JWKS 조회 실패 (\(status))."
        }
    }
}

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

    public init(
        clientId: String,
        redirectURI: URL,
        issuer: URL = URL(string: "https://api.1pass.dev")!,
        tokenIssuer: String = "https://api.1pass.dev",
        scopes: [String] = ["openid", "profile:basic", "email"]
    ) {
        self.clientId = clientId
        self.redirectURI = redirectURI
        self.issuer = issuer
        self.tokenIssuer = tokenIssuer
        self.scopes = scopes
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

public enum LogiAuthError: LocalizedError, Sendable {
    case notConfigured
    case invalidAuthorizeURL
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

    public var errorDescription: String? {
        switch self {
        case .notConfigured:
            return "LogiAuth.configure(_:) 가 호출되지 않았습니다."
        case .invalidAuthorizeURL:
            return "/oauth/authorize URL을 만들 수 없습니다."
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
        case .jwksFetchFailed(let status):
            return "JWKS 조회 실패 (\(status))."
        }
    }
}

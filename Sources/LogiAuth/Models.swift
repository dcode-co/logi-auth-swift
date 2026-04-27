import Foundation

public struct LogiAuthConfig: Sendable {
    public let clientId: String
    /// Redirect URI registered with the logi IdP. Recommended: a claimed HTTPS
    /// URL on your RP domain (Universal Link) so the IdP app can hand the
    /// authorization code back to your app via /.well-known/apple-app-site-association.
    /// Falls back to a custom-scheme URI if you cannot register a domain.
    public let redirectURI: URL
    public let issuer: URL
    public let scopes: [String]

    public init(
        clientId: String,
        redirectURI: URL,
        issuer: URL = URL(string: "https://api.1pass.dev")!,
        scopes: [String] = ["openid", "profile:basic"]
    ) {
        self.clientId = clientId
        self.redirectURI = redirectURI
        self.issuer = issuer
        self.scopes = scopes
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
        }
    }
}

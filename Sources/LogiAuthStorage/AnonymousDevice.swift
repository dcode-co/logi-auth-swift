import Foundation
import LogiAuth

// MARK: - Public types

public struct AnonymousDeviceResult: Sendable {
    public let accessToken: String
    public let tokenType: String
    public let expiresIn: Int?
    public let userId: Int
    public let nickname: String?
    public let anonymous: Bool
    public init(accessToken: String, tokenType: String, expiresIn: Int?, userId: Int, nickname: String?, anonymous: Bool) {
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.expiresIn = expiresIn
        self.userId = userId
        self.nickname = nickname
        self.anonymous = anonymous
    }
}

// MARK: - Anonymous device bootstrap (PAK)

/// SDK helper for the anonymous-first sign-in pattern used by RPs whose
/// "guest mode" must persist across launches (e.g. jesus_talk's
/// confession flow with `allow_anonymous=true`). Before this helper
/// existed, every RP had to reimplement the (device_id, device_secret)
/// dance against `/api/v1/auth/anonymous_bootstrap` themselves.
///
/// Contract (mirrors POST /api/v1/auth/anonymous_bootstrap):
///   1. First call generates a stable `device_id` (UUID), persists it to
///      Keychain, and POSTs without `device_secret`. Server returns
///      `device_secret` ONCE. We persist that too.
///   2. Subsequent calls POST with the stored `device_secret`. Server
///      verifies it and returns a fresh PAK.
///   3. On `invalid_device_secret` (Keychain wipe vs server out-of-sync)
///      we wipe the local secret and retry as a fresh bootstrap exactly
///      once.
///
/// Server platform whitelist: ios|macos only. Android intentionally
/// excluded — Android SDK will not expose this surface until the server
/// adds the platform.
public actor LogiAuthAnonymousDevice {

    private let issuer: URL
    private let clientId: String
    private let urlSession: URLSession
    private let keychainService: String
    /// Coalesces concurrent bootstrap() calls so the first-bootstrap
    /// race (URLSession.data suspension before device_secret is
    /// persisted) cannot cause a second call to also create a fresh
    /// credential. (codex review 2026-05-18)
    private var inFlight: Task<AnonymousDeviceResult, Error>?

    /// One instance per RP `clientId`. Keychain entries are namespaced
    /// by clientId so multiple LogiAuth-using RPs sharing the same
    /// bundle (e.g. an app extension + container) do not collide on the
    /// device credential. (codex review 2026-05-18)
    public init(issuer: URL, clientId: String, urlSession: URLSession = .shared) {
        self.issuer = issuer
        self.clientId = clientId
        self.urlSession = urlSession
        self.keychainService = "dev.1pass.LogiAuth.anonymous.\(clientId)"
    }

    private static let deviceIdKey = "anonymous_device_id"
    private static let deviceSecretKey = "anonymous_device_secret"

    /// Returns a PAK bound to the device's anonymous user. Idempotent
    /// across launches and across concurrent callers within a process.
    public func bootstrap(deviceName: String? = nil) async throws -> AnonymousDeviceResult {
        if let inFlight { return try await inFlight.value }
        let task = Task { try await perform(deviceName: deviceName, allowReset: true) }
        inFlight = task
        defer { inFlight = nil }
        return try await task.value
    }

    /// Drop the stored anonymous credential. RP must call this on
    /// explicit sign-out so the next `bootstrap()` starts fresh.
    public func reset() {
        let kc = Keychain(service: keychainService)
        kc.delete(Self.deviceIdKey)
        kc.delete(Self.deviceSecretKey)
    }

    // MARK: - Implementation

    private func perform(deviceName: String?, allowReset: Bool) async throws -> AnonymousDeviceResult {
        let kc = Keychain(service: keychainService)
        let deviceId = kc.get(Self.deviceIdKey) ?? {
            let fresh = UUID().uuidString
            kc.set(fresh, for: Self.deviceIdKey)
            return fresh
        }()
        let storedSecret = kc.get(Self.deviceSecretKey)

        var body: [String: String] = [
            "device_id": deviceId,
            "device_platform": Self.currentPlatform
        ]
        if let storedSecret { body["device_secret"] = storedSecret }
        if let deviceName { body["device_name"] = deviceName }

        let url = issuer.appendingPathComponent("api/v1/auth/anonymous_bootstrap")
        var request = URLRequest(url: url)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await urlSession.data(for: request)
        let status = (response as? HTTPURLResponse)?.statusCode ?? 0

        // Recovery: server-side state ahead of our Keychain (wipe / device
        // restore). Reset local secret + retry as fresh bootstrap exactly
        // once.
        if status == 401, allowReset, Self.errorCode(from: data) == "invalid_device_secret" {
            kc.delete(Self.deviceSecretKey)
            return try await perform(deviceName: deviceName, allowReset: false)
        }

        guard (200..<300).contains(status) else {
            throw LogiAuthError.tokenExchangeFailed(status: status, body: String(data: data, encoding: .utf8) ?? "")
        }

        let decoded: BootstrapResponse
        do {
            decoded = try JSONDecoder().decode(BootstrapResponse.self, from: data)
        } catch {
            // Wrap raw DecodingError in SDK error type with full body
            // context — surface is consistent with /oauth/token failures.
            throw LogiAuthError.tokenExchangeFailed(status: status, body: String(data: data, encoding: .utf8) ?? "decode_failed: \(error)")
        }
        if let newSecret = decoded.device_secret { kc.set(newSecret, for: Self.deviceSecretKey) }

        return AnonymousDeviceResult(
            accessToken: decoded.access_token,
            tokenType: decoded.token_type,
            expiresIn: decoded.expires_in,
            userId: decoded.user.id,
            nickname: decoded.user.nickname,
            anonymous: decoded.user.anonymous
        )
    }

    private static func errorCode(from data: Data) -> String? {
        (try? JSONSerialization.jsonObject(with: data) as? [String: Any])?["error"] as? String
    }

    private static var currentPlatform: String {
        #if os(macOS)
        return "macos"
        #else
        return "ios"
        #endif
    }

    private struct BootstrapResponse: Decodable {
        let access_token: String
        let token_type: String
        let expires_in: Int?
        let device_secret: String?
        let user: User
        struct User: Decodable {
            let id: Int
            let anonymous: Bool
            let nickname: String?
        }
    }
}

import Foundation
import LogiAuth

// MARK: - Public types

/// The verified outcome of a device-key exchange.
public struct LogiDeviceKeyResult: Sendable {
    /// device-bound PAK (`logi_pak_...`). Bearer for all `/api/v1/*` calls.
    public let pak: String
    public let scopes: [String]
    /// Server DeviceCredential id, if the response carried one (probed at
    /// top-level `device_id`, `device.id`, or `user.device_id`). `nil` when the
    /// response omits it — the record-id field is not yet part of the contract.
    public let deviceRecordID: String?

    public init(pak: String, scopes: [String], deviceRecordID: String?) {
        self.pak = pak
        self.scopes = scopes
        self.deviceRecordID = deviceRecordID
    }
}

// MARK: - Device-bound PAK exchange

/// Exchanges an OAuth **JWT** (from `LogiAuth.signIn()`) for a device-bound
/// **PAK** (`logi_pak_...`) against `POST /api/v1/me/device_keys/exchange`.
///
/// LogiAuth's access token is an RS256 JWT, but the logi `/api/v1/*` surface
/// requires a device-bound PAK — the JWT alone will not authenticate there.
/// Before this helper existed, an RP had to hand-roll the (device_uuid,
/// device_secret) dance itself (logi focus's `DeviceKeyExchange`). This actor
/// folds that into the SDK so every RP shares one audited implementation.
///
/// Contract (mirrors `POST /api/v1/me/device_keys/exchange`):
///   1. First call generates a stable `device_uuid` (UUID), persists it to the
///      Keychain, and POSTs without `device_secret`. The server returns
///      `device_secret` ONCE; we persist it too.
///   2. Subsequent calls POST with the stored `device_secret`; the server
///      verifies it and returns a fresh PAK.
///   3. The device record id (`device_id`) is not a guaranteed response field
///      yet, so we probe the likely locations and keep `nil` when absent.
///
/// Mirrors `LogiAuthAnonymousDevice`: one instance per RP `clientId`, Keychain
/// entries namespaced by service, and concurrent `exchange()` calls coalesced so
/// the first-exchange race (URLSession suspension before `device_secret` is
/// persisted) cannot mint a second credential. (codex review 2026-05-18 pattern)
public actor LogiDeviceKey {

    private let base: URL
    private let clientId: String
    private let urlSession: URLSession
    private let keychainService: String
    private var inFlight: Task<LogiDeviceKeyResult, Error>?

    /// - Parameters:
    ///   - issuer: logi API origin (the same value `LogiAuth` is configured with).
    ///   - clientId: the RP's client_id. Used to namespace the default Keychain
    ///     service so multiple LogiAuth-using RPs in one bundle do not collide.
    ///   - keychainService: Keychain service name for the (device_uuid,
    ///     device_secret, device_record_id) triplet. Defaults to a
    ///     LogiAuth-namespaced value. An RP MIGRATING an existing install MUST
    ///     inject its legacy service name (e.g. logi focus's
    ///     `"com.dcodelabs.logicontrol.devicekey"`) so the stored device_uuid and
    ///     device_secret survive — otherwise the server mints a fresh orphan
    ///     DeviceCredential and the 10/h exchange rate-limit / 409 risk applies.
    ///   - urlSession: injectable for tests.
    public init(
        issuer: URL,
        clientId: String,
        keychainService: String? = nil,
        urlSession: URLSession = .shared
    ) {
        self.base = issuer
        self.clientId = clientId
        self.keychainService = keychainService ?? "dev.1pass.LogiAuth.device.\(clientId)"
        self.urlSession = urlSession
    }

    private static let deviceUUIDKey = "device_uuid"
    private static let deviceSecretKey = "device_secret"
    private static let deviceRecordIDKey = "device_record_id"

    /// The server DeviceCredential id from the last successful exchange, if any.
    public func storedDeviceRecordID() -> String? {
        Keychain(service: keychainService).get(Self.deviceRecordIDKey)
    }

    /// Present an OAuth JWT and exchange it for a device-bound PAK. Idempotent
    /// across launches (persisted device_uuid/secret) and coalesced across
    /// concurrent callers within the process.
    public func exchange(oauthJWT: String) async throws -> LogiDeviceKeyResult {
        if let inFlight { return try await inFlight.value }
        let task = Task { try await perform(oauthJWT: oauthJWT) }
        inFlight = task
        defer { inFlight = nil }
        return try await task.value
    }

    /// Drop the stored device credential. The RP must call this on explicit
    /// account deletion so the next `exchange()` bootstraps a fresh credential.
    public func reset() {
        let kc = Keychain(service: keychainService)
        kc.delete(Self.deviceUUIDKey)
        kc.delete(Self.deviceSecretKey)
        kc.delete(Self.deviceRecordIDKey)
    }

    // MARK: - Implementation

    private func perform(oauthJWT: String) async throws -> LogiDeviceKeyResult {
        let kc = Keychain(service: keychainService)
        let deviceUUID = kc.get(Self.deviceUUIDKey) ?? {
            let fresh = UUID().uuidString
            kc.set(fresh, for: Self.deviceUUIDKey)
            return fresh
        }()

        var body: [String: String] = [
            "device_uuid": deviceUUID,
            "platform": Self.currentPlatform
        ]
        if let secret = kc.get(Self.deviceSecretKey), !secret.isEmpty {
            body["device_secret"] = secret
        }

        var req = URLRequest(url: base.appendingPathComponent("api/v1/me/device_keys/exchange"))
        req.httpMethod = "POST"
        req.timeoutInterval = 15
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.setValue("application/json", forHTTPHeaderField: "Accept")
        req.setValue("Bearer \(oauthJWT)", forHTTPHeaderField: "Authorization")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, response) = try await urlSession.data(for: req)
        let status = (response as? HTTPURLResponse)?.statusCode ?? -1
        guard (200..<300).contains(status) else {
            // 409 device_claimed_by_other_user and every other non-2xx surface
            // through the SDK's token-exchange error with the full body so the
            // caller can branch on the server error code.
            throw LogiAuthError.tokenExchangeFailed(status: status, body: String(data: data, encoding: .utf8) ?? "")
        }

        let decoded: ExchangeResponse
        do {
            decoded = try JSONDecoder().decode(ExchangeResponse.self, from: data)
        } catch {
            throw LogiAuthError.tokenExchangeFailed(status: status, body: String(data: data, encoding: .utf8) ?? "decode_failed: \(error)")
        }

        // The server returns device_secret exactly once; persist it for the
        // idempotent re-use on later exchanges.
        if let newSecret = decoded.device_secret, !newSecret.isEmpty {
            kc.set(newSecret, for: Self.deviceSecretKey)
        }
        let recordID = decoded.resolvedDeviceRecordID
        if let recordID, !recordID.isEmpty {
            kc.set(recordID, for: Self.deviceRecordIDKey)
        }

        return LogiDeviceKeyResult(
            pak: decoded.access_token,
            scopes: decoded.scopes ?? [],
            deviceRecordID: recordID
        )
    }

    private static var currentPlatform: String {
        #if os(macOS)
        return "macos"
        #else
        return "ios"
        #endif
    }

    // MARK: - Wire contract

    private struct ExchangeResponse: Decodable {
        let access_token: String
        let token_type: String?
        let scopes: [String]?
        let device_secret: String?
        // The contract has no device-record-id field yet (gap). Optimistically
        // probe the likely locations so a later server addition needs no client
        // change: top-level `device_id`, then `device.id`, then `user.device_id`.
        let device_id: FlexID?
        let device: DeviceObj?
        let user: UserObj?

        struct DeviceObj: Decodable { let id: FlexID? }
        struct UserObj: Decodable { let device_id: FlexID? }

        var resolvedDeviceRecordID: String? {
            device_id?.stringValue ?? device?.id?.stringValue ?? user?.device_id?.stringValue
        }
    }

    /// The server may encode an id as either Int or String — accept both.
    private enum FlexID: Decodable {
        case int(Int)
        case string(String)

        init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let intValue = try? container.decode(Int.self) {
                self = .int(intValue)
            } else {
                self = .string(try container.decode(String.self))
            }
        }

        var stringValue: String {
            switch self {
            case .int(let value): return String(value)
            case .string(let value): return value
            }
        }
    }
}

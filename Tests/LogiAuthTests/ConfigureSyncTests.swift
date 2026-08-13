import XCTest
@testable import LogiAuth

/// Regression guard for the `configure()` same-tick race fixed in `a412984`.
///
/// Before that fix `configure()` deferred the assignment through
/// `Task { @MainActor in shared.config = config }`. An RP that called
/// configure → signIn inside a single MainActor tick — which is exactly what a
/// cold-start first tap does — therefore hit `.notConfigured` on the first
/// attempt and only succeeded on the second (ainote 실기 실측 2026-08-12).
///
/// The observation point is `verify(_:)`. Its guards run in the order
/// `config` → `result.idToken`, and neither branch touches the network or UI,
/// so a fixture carrying no id_token turns "is the config visible yet?" into a
/// pure error-kind assertion:
///
/// - `.notConfigured`  → config NOT visible (the regression)
/// - `.missingIdToken` → config visible, stopped by the fixture instead (pass)
///
/// `handle(_:)` cannot serve the same purpose: it checks `pendingHandoff`
/// *before* `config`, so it returns `false` either way.
@MainActor
final class ConfigureSyncTests: XCTestCase {

    /// `configure(_:)` mutates the process-global `LogiAuth.shared`, and other
    /// suites assert on unconfigured behaviour. Hand the singleton back the way
    /// we found it so this class never becomes an ordering dependency.
    override func tearDown() async throws {
        await MainActor.run { LogiAuth.resetForTesting() }
        try await super.tearDown()
    }

    /// A result that is valid enough to enter `verify` but carries no id_token,
    /// so the call always terminates before any I/O.
    private func resultWithoutIdToken() -> LogiAuthResult {
        LogiAuthResult(accessToken: "at_regression_fixture", idToken: nil)
    }

    /// A scheme owned by this test, not by any real RP — an app's scheme may
    /// change without this fixture meaning anything different.
    private func syncConfig() -> LogiAuthConfig {
        LogiAuthConfig(
            clientId: "rp_configure_sync_regression",
            redirectURI: URL(string: "logiauth-test://oauth/callback")!
        )
    }

    /// The `@MainActor` on this class is load-bearing. A same-actor `async`
    /// call performs no hop, so `verify` reaches its `config` guard before the
    /// enqueued `Task` from the old implementation could ever run — the `await`
    /// below is not a suspension in practice. De-isolating this class, or
    /// moving the assertion into a `nonisolated` helper, would enqueue the hop
    /// *after* that `Task` on the same FIFO queue; the config would then be
    /// visible and the regression would pass silently.
    func testConfigureIsVisibleWithoutAwaitingATick() async {
        LogiAuth.configure(syncConfig())

        do {
            _ = try await LogiAuth.verify(resultWithoutIdToken())
            XCTFail("verify() must throw — the fixture carries no id_token")
        } catch LogiAuthError.notConfigured {
            XCTFail("REGRESSION: configure() did not apply synchronously")
        } catch LogiAuthError.missingIdToken {
            // config was visible; the missing id_token is what stopped us.
        } catch {
            XCTFail("unexpected error: \(error)")
        }
    }
}

# logi-auth-swift

**Sign in with logi** — drop-in iOS / macOS SDK for [logi (1pass.dev)](https://1pass.dev) Relying Parties.

OAuth 2.0 Authorization Code + PKCE (S256), RFC 7636 + RFC 8252 compliant.
앱-투-앱 first, ASWebAuthenticationSession fallback.

[![SPM compatible](https://img.shields.io/badge/SPM-compatible-brightgreen.svg)](https://swift.org/package-manager)
[![Platforms](https://img.shields.io/badge/platforms-iOS%2017%2B%20%7C%20macOS%2014%2B-blue.svg)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## Install (Swift Package Manager)

### Xcode
**File → Add Package Dependencies…** 에 다음 URL 입력:
```
https://github.com/dcode-co/logi-auth-swift
```
버전: `1.1.0` 이상.

### Package.swift
```swift
dependencies: [
    .package(url: "https://github.com/dcode-co/logi-auth-swift", from: "1.1.0"),
],
targets: [
    .target(name: "MyApp", dependencies: [
        .product(name: "LogiAuth", package: "logi-auth-swift"),
        // 토큰 영속화·refresh·device PAK·revoke 를 쓰면 함께 링크:
        .product(name: "LogiAuthStorage", package: "logi-auth-swift"),
    ]),
]
```

---

## Quickstart

### 1. App 초기화
```swift
import SwiftUI
import LogiAuth

@main
struct MyApp: App {
    init() {
        LogiAuth.configure(
            LogiAuthConfig(
                clientId: "logi_xxxxxxxxxxxxxxxx",     // start.1pass.dev/developer 에서 발급
                redirectURI: URL(string: "myapp://oauth/1pass/callback")!,
                scopes: ["openid", "profile:basic", "email"]
            )
        )
    }

    var body: some Scene {
        WindowGroup {
            ContentView()
                .onOpenURL { url in
                    LogiAuth.handle(url: url)         // app-to-app callback
                }
        }
    }
}
```

### 2. 로그인 버튼
```swift
struct SignInButton: View {
    @State private var isLoading = false

    var body: some View {
        Button {
            Task {
                isLoading = true
                defer { isLoading = false }
                do {
                    let result = try await LogiAuth.signIn()
                    // result.accessToken / .idToken / .refreshToken
                    print("✅ Signed in:", result.accessToken)
                } catch {
                    print("❌", error)
                }
            }
        } label: {
            HStack {
                Image(systemName: "key.fill")
                Text("logi 로 로그인")
            }
        }
        .disabled(isLoading)
    }
}
```

### 3. Info.plist — URL scheme
```xml
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLSchemes</key>
        <array><string>myapp</string></array>
    </dict>
</array>
```

### 4. Associated Domains (app-to-app handoff 활성화)
Xcode → Signing & Capabilities → **+ Capability → Associated Domains** →
```
applinks:api.1pass.dev
```

---

## How it works

1. **App-to-app first**: `UIApplication.open(authorizeURL, options:[.universalLinksOnly:true])` 로 logi 앱이 설치된 경우 즉시 핸드오프.
2. **ASWebAuthenticationSession fallback**: 미설치 시 시스템 브라우저로 `/oauth/authorize` 페이지. `prefersEphemeralWebBrowserSession = true` 로 쿠키 누수 차단.
3. **PKCE S256**: code_verifier 는 메모리, code_challenge 만 전송.
4. **Refresh token**: `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly` 로 Keychain 저장.

자세한 플로우: [docs.1pass.dev/integrations/swift](https://docs.1pass.dev/integrations/swift)

---

## API

### `LogiAuth` (core connector — 인증만)
| Method | Returns | Description |
|---|---|---|
| `LogiAuth.configure(_:)` | `Void` | 앱 시작 시 1회 호출 |
| `LogiAuth.signIn(scopes:)` | `async throws -> LogiSession` | 로그인 (id_token RS256 서명검증 내장) |
| `LogiAuth.verify(_:)` | `async throws -> LogiSession` | `refresh()` 결과의 id_token 을 검증해 세션으로 승격 · **v1.1.0** |
| `LogiAuth.handle(_:)` | `Bool` | app-to-app callback 처리 (onOpenURL 에서 호출) |
| `LogiAuth.shared.lastSession` | `@Published LogiSession?` | SwiftUI observable |

### `LogiAuthStorage` (선택 — 토큰 영속화·백채널)
| Method | Returns | Description |
|---|---|---|
| `LogiAuthStorage(clientId:issuer:)` | — | 인스턴스 생성 |
| `.persist(_:)` / `.currentRefreshToken()` | | refresh_token Keychain 저장/조회 |
| `.refresh()` | `async throws -> LogiAuthResult` | silent refresh (미검증 — `LogiAuth.verify` 로 승격) |
| `.signOut()` | `Void` | 로컬 refresh_token 삭제 (서버 토큰은 유지) |
| `.revokeRefreshToken()` | `async` | 서버 refresh_token revoke (RFC 7009) · **v1.1.0** |
| `.disconnectApp(pak:)` | `async -> Bool` | RP 연동 해지 `DELETE connected_apps` (PAK) · **v1.1.0** |

### `LogiDeviceKey` (선택 — device-bound PAK, **v1.1.0**)
| Method | Returns | Description |
|---|---|---|
| `LogiDeviceKey(issuer:clientId:keychainService:)` | — | actor 생성 (마이그레이션 시 레거시 `keychainService` 주입) |
| `.exchange(oauthJWT:)` | `async throws -> LogiDeviceKeyResult` | OAuth JWT → device-bound PAK 교환 (멱등·in-flight 병합) |
| `.storedDeviceRecordID()` / `.reset()` | | device 자격 조회 / 삭제 |

에러 타입: `LogiAuthError` — `.notConfigured`, `.userCancelled`, `.stateMismatch`, `.handoffTimeout`, `.idTokenInvalid(code:)`, `.tokenExchangeFailed(status:body:)`, `.jwksFetchFailed(status:)` 등

---

## Compliance

- RFC 6749 (OAuth 2.0)
- RFC 7636 (PKCE S256)
- RFC 8252 (OAuth for Native Apps — system browser 만, 임베디드 WebView 금지)
- Apple Sign in with logi 디자인 가이드라인 준수 (logi pill icon spec: [docs.1pass.dev/branding](https://docs.1pass.dev/branding))

---

## Versioning

- `v1.1.x` — current stable. iOS 17+, macOS 14+
  - **v1.1.0** — `LogiAuth.verify(_:)` (refresh 경로 id_token 검증), `LogiDeviceKey`
    (device-bound PAK 교환), `LogiAuthStorage.revokeRefreshToken()` / `disconnectApp(pak:)`.
    전부 additive — 기존 심볼 시그니처 불변, 마이그레이션 불필요.
  - **v1.0.x** — id_token RS256 서명검증 내장(`signIn() -> LogiSession`), `at_hash` 바인딩,
    JWKS `kty` 필터. 토큰 영속화·refresh 는 `LogiAuthStorage` 로 분리.
- Semantic versioning. Breaking changes → major bump + migration guide.
- Tag 패턴: `vX.Y.Z`

---

## License

MIT. See [LICENSE](LICENSE).

## Issues / Support

- 🐛 [GitHub Issues](https://github.com/dcode-co/logi-auth-swift/issues)
- 📖 [docs.1pass.dev](https://docs.1pass.dev)
- 📧 dcode.labs.kr@gmail.com

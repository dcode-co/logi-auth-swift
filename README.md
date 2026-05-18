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
버전: `0.2.0` 이상.

### Package.swift
```swift
dependencies: [
    .package(url: "https://github.com/dcode-co/logi-auth-swift", from: "0.2.0"),
],
targets: [
    .target(name: "MyApp", dependencies: [
        .product(name: "LogiAuth", package: "logi-auth-swift"),
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

| Method | Returns | Description |
|---|---|---|
| `LogiAuth.configure(_:)` | `Void` | 앱 시작 시 1회 호출 |
| `LogiAuth.signIn(scopes:)` | `async throws -> LogiAuthResult` | 로그인 플로우 시작 |
| `LogiAuth.refresh()` | `async throws -> LogiAuthResult` | silent refresh |
| `LogiAuth.signOut()` | `Void` | 저장된 refresh token 삭제 |
| `LogiAuth.handle(url:)` | `Bool` | app-to-app callback 처리 (onOpenURL 에서 호출) |
| `LogiAuth.shared.lastResult` | `@Published` | SwiftUI observable |

에러 타입: `LogiAuthError.notConfigured`, `.userCancelled`, `.stateMismatch`, `.tokenEndpoint(_)`, `.network(_)`

---

## Compliance

- RFC 6749 (OAuth 2.0)
- RFC 7636 (PKCE S256)
- RFC 8252 (OAuth for Native Apps — system browser 만, 임베디드 WebView 금지)
- Apple Sign in with logi 디자인 가이드라인 준수 (logi pill icon spec: [docs.1pass.dev/branding](https://docs.1pass.dev/branding))

---

## Versioning

- `v0.2.x` — current stable. iOS 17+, macOS 14+
- Semantic versioning. Breaking changes → major bump + migration guide.
- Tag 패턴: `vX.Y.Z`

---

## License

MIT. See [LICENSE](LICENSE).

## Issues / Support

- 🐛 [GitHub Issues](https://github.com/dcode-co/logi-auth-swift/issues)
- 📖 [docs.1pass.dev](https://docs.1pass.dev)
- 📧 dcode.labs.kr@gmail.com

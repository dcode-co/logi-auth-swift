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

> ⚠️ **configure 는 반드시 앱 시작 시(App.init) 호출한다.** 로그인 버튼 탭
> 핸들러에서 처음 configure 하는 패턴은 금지 — 두 경로로 깨진다.
> ① 구버전(≤v1.2.x)은 configure 가 `Task { @MainActor }` 로 **비동기 반영**이라,
> 같은 MainActor 틱에서 configure → signIn 이 이어지면 첫 탭만 `.notConfigured`
> 로 실패하고 두 번째 탭부터 성공하는 race 가 있었다 (ainote 실기 실측
> 2026-08-12 — 현재는 동기 반영으로 수정됨).
> ② 콜백만으로 콜드 스타트한 프로세스(app-to-app 복귀·프로세스 재생성)는 탭
> 없이 `handle(_:)` 에 도달하는데, configure 가 없으면 SDK 가 redirect_uri
> 매칭을 못 해 콜백을 **에러 없이 조용히 무시**하고 RP 의 다른 URL 핸들러로
> 흘러갈 수 있다 (진행 중이던 sign-in 은 프로세스와 함께 소멸 — 정답은 재시도).
> 어느 버전에서든 App.init 1회 호출이 정답이다.

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
| `LogiAuth.configure(_:)` | `Void` | 앱 시작 시 1회 호출 · **동기 반영** (리턴 즉시 `signIn()`/`handle(_:)` 이 config 를 본다) |
| `LogiAuth.signIn(scopes:)` | `async throws -> LogiSession` | 로그인 (id_token RS256 서명검증 내장) |
| `LogiAuth.verify(_:)` | `async throws -> LogiSession` | `refresh()` 결과의 id_token 을 검증해 세션으로 승격 · **v1.1.0** |
| `LogiAuth.handle(_:)` | `Bool` | app-to-app callback 처리 (onOpenURL 에서 호출) |
| `LogiAuth.cancel()` | `Bool` | 진행 중 `signIn()` 을 `.userCancelled` 로 중단 · **v1.2.0** |
| `LogiAuth.handoffKind` | `LogiHandoffKind?` | 진행 중인 갈래(`.native`/`.web`), 없으면 nil · **v1.2.0** |
| `LogiAuth.shared.lastSession` | `@Published LogiSession?` | SwiftUI observable |

#### 승인 없이 돌아온 사용자 끊기 (`cancel()`)

app-to-app 갈래는 사용자가 logi 앱에서 **승인하지 않고 돌아와도 iOS 가 아무 신호를 주지
않는다.** `signIn()` 은 5분 `.handoffTimeout` 까지 매달리고, 그 사이 모든 `signIn()` 은
`.alreadyInProgress` 로 튕긴다. 이탈 판정은 RP 몫이고, 그 판정을 SDK 로 전달하는 통로가
`cancel()` 이다.

🔴 **`handoffKind == .native` 로 반드시 게이트할 것.** 웹 갈래는 ASWebAuthenticationSession
시트가 화면에 떠 있고 시스템이 이미 취소를 알려주므로, 홈으로 나갔다 돌아온 것은 이탈이
아니다. 무조건 `cancel()` 하면 **멀쩡히 살아있는 웹 로그인을 끊는다.**

```swift
.onChange(of: scenePhase) { _, phase in
    guard phase == .active, LogiAuth.handoffKind == .native else { return }
    // 콜백 도착과 foreground 전환의 순서는 보장되지 않는다 — 짧은 유예를 둔다.
    Task {
        try? await Task.sleep(for: .seconds(2))
        // 🔴 유예가 끝난 뒤 다시 확인한다. 그 사이 원래 흐름이 콜백으로
        // 끝났을 수 있고, `cancel()` 은 "지금 진행 중인" 흐름에 작용하므로
        // 재확인 없이 부르면 그새 시작된 다른 로그인을 끊는다.
        guard LogiAuth.handoffKind == .native else { return }
        LogiAuth.cancel()
    }
}
```

> 재확인해도 완전히 닫히지는 않는다 — 유예 2초 안에 **또 다른 app-to-app 로그인**이
> 시작되면 그것을 끊는다. 사용자가 2초 안에 재시도하고 다시 앱을 이탈해야 하는
> 조합이라 실사용에서는 드물지만, 정확성이 필요하면 유예를 줄이거나 RP 가 자체
> 요청 id 로 게이트할 것.

> Android SDK 는 `configure()` 에서 `registerCancelDetector` 로 **SDK 가 직접** 이탈을
> 감지한다. iOS 는 씬 구조 가정을 피하려 판정을 RP 에 남겼다 — 같은 문제, 다른 층.

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

전체 이력은 [CHANGELOG.md](CHANGELOG.md).

- `v1.3.x` — authorize 핸드오프 호스트 분리. iOS 17+
  - **v1.3.0** — `signIn()` 의 네이티브 app-to-app 갈래가 `open.1pass.dev` 로,
    웹 폴백은 `issuer` 호스트(`api.1pass.dev`)로 간다. 쿼리는 동일하고 host 만 다르다.
    `api.1pass.dev` 의 `/oauth/authorize*` claim 이 웹 RP 의 브라우저 로그인까지
    가로채던 문제를 푼다.
    설정: `LogiAuthConfig.nativeAuthorizeHost`(기본 `nil`) —
    stock 프로덕션 issuer 일 때만 자동 파생하고, 스테이징·자체호스팅은 두 갈래 모두
    issuer 호스트에 남는다.
    🔴 `issuer` 는 그대로다 — 토큰 교환·JWKS·`iss` 검증이 같은 값을 쓴다.
    `authorize(startURL:)`(백엔드 주도 BFF 흐름)도 이 버전에 실리며, **호스트 분리
    대상은 아니다**(호스트를 백엔드가 정하는 구조).
    심볼 시그니처 불변 — 추가만 한다.
- `v1.2.x` — iOS 17+, macOS 14+
  - **v1.2.0** — `LogiAuth.cancel()` + `LogiAuth.handoffKind`. app-to-app 갈래에서
    승인 없이 돌아온 사용자를 RP 가 끊을 수 있다(이전에는 5분 타임아웃까지 대기).
    심볼 시그니처 불변 — 추가만 한다.
    ⚠️ **동작 변경 1건**: `.alreadyInProgress` 가드가 모든 갈래를 덮는다. 이전에는
    `pendingHandoff` 만 봐서 **커스텀 스킴 redirect URI** RP 는 `signIn()` 중복 호출이
    통과했고, 두 흐름이 단일 ASWAS 슬롯을 공유해 먼저 뜬 쪽 continuation 이 영영
    해소되지 않았다. 이제 두 번째 호출은 `.alreadyInProgress` 를 던진다. HTTPS
    redirect URI RP 는 영향 없다(이전에도 가드에 걸렸다).
- `v1.1.x`
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

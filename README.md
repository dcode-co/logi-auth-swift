# LogiAuth

Drop-in **Sign in with logi** SDK for iOS Relying Parties.

```swift
.package(url: "https://github.com/seunghan91/logi", from: "0.1.0", path: "Packages/LogiAuth")
```

## Usage

```swift
import LogiAuth

@main
struct MyApp: App {
    init() {
        LogiAuth.configure(
            LogiAuthConfig(
                clientId: "rp_xxx",                                   // issued by logi developer portal
                redirectURI: URL(string: "https://myapp.com/oauth/callback")!,
                scopes: ["openid", "profile:basic", "email"]
            )
        )
    }

    var body: some Scene {
        WindowGroup { ContentView() }
    }
}

struct SignInButton: View {
    var body: some View {
        Button("logi 로 로그인") {
            Task {
                let result = try await LogiAuth.signIn()
                // result.accessToken / .idToken / .refreshToken
            }
        }
    }
}
```

## How it works
1. The SDK opens `https://api.1pass.dev/oauth/authorize?…` in a system
   `ASWebAuthenticationSession` (RFC 8252 compliant — system browser, never an
   embedded WebView).
2. iOS checks the Universal Link AASA at `api.1pass.dev`; if the **logi app**
   is installed it intercepts the URL and renders a native Liquid Glass consent
   screen. If the app is not installed, the user sees the web consent page.
3. After approval, logi redirects to your `redirectURI` with `?code=…&state=…`.
4. The SDK validates `state`, exchanges the code at `/oauth/token` with the
   PKCE verifier (S256), and returns `LogiAuthResult { accessToken, idToken,
   refreshToken }`. The refresh token is stored in Keychain.

## Required RP setup
1. Register your app at https://start.1pass.dev/developer to receive a
   `client_id` and to whitelist your `redirect_uri`.
2. Host an AASA file at `https://<your-domain>/.well-known/apple-app-site-association`
   that claims your callback path so the redirect lands inside your app.
3. Add the **Associated Domains** capability with `applinks:<your-domain>`.

## API
- `LogiAuth.configure(_: LogiAuthConfig)` — call once at app start
- `LogiAuth.signIn(scopes:)` — async; returns `LogiAuthResult`
- `LogiAuth.refresh()` — silent token refresh
- `LogiAuth.signOut()` — wipe stored refresh token
- `LogiAuth.shared.lastResult` — `@Published`; observable from SwiftUI

## Compliance
- RFC 6749 + RFC 7636 (OAuth 2.0 + PKCE S256)
- RFC 8252 (OAuth for Native Apps — system browser, never embedded WebView)
- Refresh tokens stored with `kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly`
- `prefersEphemeralWebBrowserSession = true` to prevent cookie leakage

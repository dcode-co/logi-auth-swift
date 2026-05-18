import Foundation
#if canImport(UIKit)
import UIKit
#endif

/// In-app browser detection + escape helpers.
///
/// Most Korean / global social apps (KakaoTalk, Naver, Facebook, Instagram,
/// Line, WeChat, TikTok, Twitter, ...) embed pages in a WebView that
/// suppresses Universal Link handoff. As a result, a logi sign-in started
/// inside one of these in-app browsers will silently fail to launch the
/// logi app — the user just sees the web `/oauth/authorize` page with no
/// path to native handoff.
///
/// The mitigation is platform-specific:
///
///   - **Web (npm `@logi-auth/browser`)**: detect the in-app UA and render
///     a CTA that opens the current URL in the system browser via the
///     app's own deep-link escape (e.g. `kakaotalk://web/openExternal?url=…`).
///   - **Native iOS RP**: this file. RPs that present a WebView themselves
///     (e.g. an in-app browser for sharing pages) can call
///     `LogiAuthBrowser.detect(userAgent:)` on the incoming UA and, if
///     it's an in-app browser, redirect to the corresponding `escapeURL(for:)`
///     scheme before launching sign-in.
///
/// Native iOS app→logi handoff itself isn't affected by these browsers
/// (signIn() uses `UIApplication.open(.universalLinksOnly:true)` which
/// bypasses any in-app WebView). These helpers are for RPs whose own UI
/// embeds a WebView OR for sites loaded via the npm SDK.
public enum LogiAuthBrowser {

    /// Identified in-app browser environments. `unknown` means the UA looks
    /// like a normal mobile browser — no escape needed.
    public enum InApp: String, CaseIterable, Sendable {
        case kakaoTalk
        case naver
        case facebook
        case instagram
        case line
        case weChat
        case tikTok
        case twitter

        /// Case-insensitive regex matches against the User-Agent header.
        /// Patterns sourced from canonical industry detectors (Naver/Kakao
        /// SDK + Korean OAuth community 2025 audit). Mirrored exactly in
        /// the Android SDK (LogiAuthBrowser.kt) — keep in sync.
        public var pattern: String {
            switch self {
            case .kakaoTalk: return "KAKAOTALK"
            case .naver:     return "NAVER\\(inapp"   // literal "(" — escape for NSRegularExpression
            case .facebook:  return "FB_IAB|FBAN|FBAV"
            case .instagram: return "Instagram"
            case .line:      return "Line/"
            case .weChat:    return "MicroMessenger"
            case .tikTok:    return "BytedanceWebview|musical_ly"
            case .twitter:   return "Twitter for iPhone|Twitter for iPad"
            }
        }
    }

    /// Identify the in-app browser environment from a User-Agent string.
    /// Returns nil when the UA doesn't match any known in-app browser.
    ///
    /// Pure function for testability — no UIKit / Foundation network calls.
    public static func detect(userAgent: String) -> InApp? {
        for env in InApp.allCases {
            if userAgent.range(of: env.pattern, options: [.regularExpression, .caseInsensitive]) != nil {
                return env
            }
        }
        return nil
    }

    /// Build a deep-link URL that asks the host in-app browser to re-open
    /// `targetURL` in the system browser. Returns nil when the in-app
    /// browser doesn't expose a workable escape scheme — in that case the
    /// RP should show a copy-URL CTA + manual instructions.
    ///
    /// Sources:
    /// - KakaoTalk: `kakaotalk://web/openExternal?url=…` —
    ///   **community-documented (Kakao DevTalk)**, not in official Kakao
    ///   SDK docs. Widely used in production by Korean RPs; works on
    ///   current KakaoTalk versions but no SLA from Kakao.
    /// - Naver: `naversearchapp://inappbrowser?url=…&target=new` —
    ///   published in NAVER Developers mobile-app URL scheme guide.
    /// - LINE: there is **no public scheme** to escape LINE's in-app
    ///   browser from inside it (the `openExternalBrowser=1` query-param
    ///   trick only works when the URL is opened from a LINE chat, not
    ///   after the user is already inside the in-app browser). Return nil
    ///   and let the caller render copy-URL UX.
    /// - Facebook / Instagram / WeChat / TikTok / Twitter publish no
    ///   escape scheme.
    public static func escapeURL(for inApp: InApp, targetURL: URL) -> URL? {
        // Strict per-component encoding for a query value — `?`, `&`, `=`
        // must be percent-encoded so they don't break the outer URL.
        // `.urlQueryAllowed` is wrong here (it permits them as separators).
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")  // RFC 3986 unreserved
        guard let encoded = targetURL.absoluteString
            .addingPercentEncoding(withAllowedCharacters: allowed)
        else { return nil }
        switch inApp {
        case .kakaoTalk: return URL(string: "kakaotalk://web/openExternal?url=\(encoded)")
        case .naver:     return URL(string: "naversearchapp://inappbrowser?url=\(encoded)&target=new")
        default:         return nil
        }
    }

    #if canImport(UIKit)
    /// Convenience: detect via the current process's webview UA (or pass an
    /// explicit one) and open the escape URL if available. Returns true
    /// when an escape was triggered, false when the caller should fall
    /// back to manual UX (copy URL / show external-browser prompt).
    @MainActor
    @discardableResult
    public static func tryEscape(targetURL: URL, userAgent: String) -> Bool {
        guard let inApp = detect(userAgent: userAgent),
              let escape = escapeURL(for: inApp, targetURL: targetURL)
        else { return false }
        UIApplication.shared.open(escape)
        return true
    }
    #endif
}

# Changelog

Semantic versioning. 태그 패턴 `vX.Y.Z`.

---

## v1.4.1

- `LogiAuthConfig.prefersEphemeralWebSession: Bool = true` — ASWAS 웹 폴백의 쿠키 정책을
  RP 가 정한다. 기본은 기존과 같은 ephemeral(비공유). 웹 폴백이 로그인 전부인 사용자
  (logi 앱 미설치)가 반복 로그인하는 RP 는 `false` 로 Safari 세션 쿠키를 재사용한다 —
  SDK 이전 meetnote 코디네이터가 의도적으로 켜 두던 동작의 복원 (codex P2).
  additive — 기존 호출부 무변경.

## v1.4.0

### BFF `authorize()` 에도 호스트 분리 — 단, 명시적으로

`authorize(startURL:nativeStartURL:)` — 네이티브 앱-투-앱 first-try 갈래만 `nativeStartURL` 로,
웹 폴백은 `startURL` 그대로. v1.3.0 이 signIn() 에 자동 파생으로 넣은 분리를 BFF surface 는
**명시 파라미터**로 받는다. BFF start URL 은 RP 백엔드의 정책 객체(스테이징·프록시·서명 URL)라
SDK 가 임의로 변형하면 non-stock 배포가 깨진다 — v1.3.0 CHANGELOG 가 "명시적 opt-in 으로"
남겨 둔 바로 그 지점이다. 첫 BFF 소비자(meetnote)가 생기면서 채워졌다.

- 두 URL 은 같은 인가 요청이어야 한다. **launch 전에** 검증한다 — `state` 누락/빈값은
  `.missingStateInStartURL`, 중복 `state` 키 또는 호스트 외의 어떤 차이(쿼리 byte·path·port·
  scheme)든 신규 `.startURLPairMismatch`. state 만 비교하면 redirect_uri drift 가 핸드오프를
  타임아웃까지 방치하고 PKCE drift 가 인증 후 교환을 깨뜨린다(codex P2). 거부 시점에는
  아무것도 열려 있지 않다(single-flight 락도 잡기 전).
- 권장 구성: 웹 URL 하나를 만들고 네이티브 URL 은 **호스트만 치환**해 파생 — 쿼리(state·nonce·
  code_challenge)가 바이트 단위로 같아져 drift 가 구조적으로 불가능하다.
- `nativeStartURL` 생략 = 기존 동작(양 갈래 `startURL`). claim 이 issuer 호스트에서 내려간 뒤에는
  생략형의 first-try 가 앱을 못 띄우게 되므로, BFF RP 는 분리형으로 이동해야 한다.

### 호환성

- 추가만 한다. 기존 `authorize(startURL:)` 호출은 시그니처·동작 모두 불변.
- `LogiAuthError` 에 `.startURLPairMismatch` 추가 — exhaustive switch 를 쓰는 RP 는 분기 하나가
  필요하다(알려진 소비자 중엔 없음).

---

## v1.3.0 — 미출시 (태그 대기)

### authorize 핸드오프 호스트 분리

`signIn()` 의 두 갈래가 서로 다른 호스트를 쓴다. 쿼리는 동일하고 host 만 다르다.

| 갈래 | 호스트 | 이유 |
|---|---|---|
| 네이티브 app-to-app 핸드오프 | `open.1pass.dev` | AASA 가 `/oauth/authorize*` 를 claim → `UIApplication.open(.universalLinksOnly:)` 가 logi 앱을 띄운다 |
| 웹 폴백(ASWebAuthenticationSession) | `issuer` 호스트 = `api.1pass.dev` | claim 이 **없어야** 브라우저 로그인이 가로채이지 않는다 |

**해결한 문제**: `api.1pass.dev` 의 `/oauth/authorize*` claim 이 네이티브 SSO 용으로
들어갔지만 같은 URL 을 쓰는 웹 RP 의 브라우저 OAuth 까지 가로챘다. 크롬에서 시작한
로그인이 logi 앱에 잡히고 콜백이 OS 기본 브라우저로 열려 세션 쿠키가 따라오지 않았다
(axhub `state mismatch` 사고).

🔴 **웹 폴백은 절대 claim 된 호스트로 가면 안 된다.** 그 갈래에 도달하는 사용자는
logi 앱 **미설치** 사용자뿐이고, 그들에게는 그 갈래가 로그인 전부다.
`AuthorizeHostSplitTests.testWebFallbackIsNeverOnTheClaimedHandoffHost` 가 고정한다.

### 추가

- `LogiAuthConfig.nativeAuthorizeHost: String?` — 네이티브 핸드오프 전용 호스트.
  기본 `nil`. init 파라미터도 기본값이 있어 기존 호출부는 무변경.
- `LogiAuthConfig.resolvedNativeAuthorizeHost` — 실제로 쓰이는 값.
  명시값 우선 → 없으면 **stock 프로덕션 issuer 일 때만** `open.1pass.dev` 로 파생.
- `LogiAuthConfig.defaultIssuer` / `LogiAuthConfig.defaultNativeAuthorizeHost`.

### 스테이징·자체호스팅은 파생하지 않는다

`issuer` 가 `https://api.1pass.dev` 가 아니면 두 갈래 모두 그 issuer 호스트에 남는다
(= v1.2.0 동작). `open.1pass.dev` 는 프로덕션 호스트라, 스테이징 RP 의 핸드오프를
거기로 보내면 **다른 배포에 authorize 요청을 던지게 된다.** 자체 배포가 부처를
운영한다면 `nativeAuthorizeHost` 로 직접 지정한다.

### `issuer` 는 그대로다

토큰 교환(`/oauth/token`)·JWKS(`/.well-known/jwks.json`)·id_token `iss` 검증·
`LogiAuthStorage` 의 revoke/connected_apps/anonymous_bootstrap 은 전부 `issuer` 바인딩을
유지한다. 옮기면 인가 코드 교환이 깨져 **모든** 로그인이 실패한다.
`ONE_PASS_ISSUER` 류 환경변수로 호스트를 우회하려는 시도는 이 경계를 넘으므로 금지.

### `authorize(startURL:)` (BFF 흐름)은 분리 대상 제외

호스트를 **RP 백엔드가** 정하는 구조라 SDK 가 클라이언트 기본값으로 덮는 것은
정책 결정이 된다. 스톡 호스트가 아닌 백엔드를 깨뜨릴 수 있어 넣지 않았다.
현재 미릴리스라 소비자가 없어 영향받는 RP 도 없다. 네이티브·웹 두 갈래 모두
`startURL` 을 그대로 쓴다. BFF RP 가 실제로 나오면 수정 위치는 백엔드(발행하는 URL 에
핸드오프 호스트를 담는다) 또는 이 SDK 의 명시적 opt-in 이다.

`authorize(startURL:)` 자체(백엔드 주도 로그인)도 이 버전에 처음 실린다.

### 호환성

- 심볼 시그니처 불변, 추가만 한다. 마이그레이션 불필요.
- **동작 변경 1건**: stock 프로덕션 issuer 를 쓰는 RP 는 재컴파일만으로 네이티브
  핸드오프 대상이 `api.1pass.dev` → `open.1pass.dev` 로 바뀐다. 서버측 부처와
  AASA 가 먼저 배포돼 있어야 한다.

---

## v1.2.0

`LogiAuth.cancel()` + `LogiAuth.handoffKind`. app-to-app 갈래에서 승인 없이 돌아온
사용자를 RP 가 끊을 수 있다(이전에는 5분 타임아웃까지 대기).

⚠️ **동작 변경 1건**: `.alreadyInProgress` 가드가 모든 갈래를 덮는다. 이전에는
`pendingHandoff` 만 봐서 **커스텀 스킴 redirect URI** RP 는 `signIn()` 중복 호출이
통과했고, 두 흐름이 단일 ASWAS 슬롯을 공유해 먼저 뜬 쪽 continuation 이 영영
해소되지 않았다. 이제 두 번째 호출은 `.alreadyInProgress` 를 던진다. HTTPS
redirect URI RP 는 영향 없다.

## v1.1.0

`LogiAuth.verify(_:)` (refresh 경로 id_token 검증), `LogiDeviceKey`
(device-bound PAK 교환), `LogiAuthStorage.revokeRefreshToken()` /
`disconnectApp(pak:)`. 전부 additive.

## v1.0.x

id_token RS256 서명검증 내장(`signIn() -> LogiSession`), `at_hash` 바인딩,
JWKS `kty` 필터. 토큰 영속화·refresh 는 `LogiAuthStorage` 로 분리.

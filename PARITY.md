# PHP client parity

This Go client implements the current PHP identity contract (`id` and `email`), following PHP commit `b35909368b3bd78bb3c7401c694aef02d6a560dd`. The language API uses exported methods, immutable user accessors and explicit error returns.

| PHP source | Go equivalent |
| --- | --- |
| `Authenticator.php` | `Authenticator` |
| `AuthUser.php` | `AuthUser` |
| `User.php` | `User (deprecated)` |
| `Token.php` | `Token` |
| `SessionData.php` | `SessionData` |
| `GlobalSessionContainer.php` | `GlobalSessionContainer` |
| `RedirectHandler.php` | `RedirectHandler / redirect control flow` |
| `ProviderUri/BaseProviderUri.php` | `providerURI / normalizeBaseURI` |
| `ProviderUri/LoginUri.php` | `NewLoginURI` |
| `ProviderUri/LogoutUri.php` | `NewLogoutURI` |
| `ProviderUri/AdminUri.php` | `NewAdminURI` |
| `ResponseData/BaseResponseData.php` | `BaseResponseData` |
| `ResponseData/UserResponseData.php` | `UserResponseData` |
| `AuthwaveException.php` | `Go error values` |
| `SessionNotStartedException.php` | `ErrSessionNotStarted` |
| `NotLoggedInException.php` | `ErrNotLoggedIn` |
| `InsecureProtocolException.php` | `ErrInsecureProtocol` |
| `InvalidUserDataSerializationException.php` | `ErrInvalidUserDataSerialization` |
| `ResponseCipherDecryptionException.php` | `ErrResponseCipherDecryption` |

## Exchange behavior

- XSalsa20-Poly1305 secretbox, 32 raw key bytes, 24-byte nonces and standard base64 match PHP Sodium. Fixed-IV tests compare complete encrypted request URLs byte for byte.
- The final underscore splits deployment ID and secret. Provider query parameters are `c`, `d`, `i`, `u`; return destinations use UTF-8 hexadecimal encoding and RFC1738 form escaping.
- Login stores its token and original query. Already authenticated login is a no-op. Token-only sessions stay logged out.
- Construction restores users, decrypts responses with the session IV, saves the user, marks and invokes the callback, then redirects to remove response data and restore the saved query.
- Callback failures propagate after the marker is saved; replay does not retry the callback. Runtime adapters persist changes on failure.
- Unsolicited responses without session state are cleaned without authenticating. Tampered ciphertext fails authentication.
- Logout removes only authentication state before redirect. Explicit destinations override the configured return URI, then the provider default. Query-only destinations replace the current query.
- Fake login stores synthetic data, appends its own response query and defers refreshing the current user until the redirected request. Only the default fake email takes the local logout branch.
- The low-level token decoder uses the request IV and accepts `uuid` or `id`; the normal response path uses the secret session IV and `id`. Extra fields are ignored, matching the current PHP client.
- Administration links point to `/admin/` and do not grant access. HTTPS is required except for `localhost`, the literal `127.0.0.127`, and HTTP providers with a `.test` hostname suffix.
- The unused legacy session-store constant and deprecated user alias/getter are retained. Actual storage uses `Authwave\SessionData`.

## Runtime adaptations

There is no implicit global browser session. Callers provide a per-request container or use a framework adapter. JSON serialization restores tokens and response objects. Session records contain secrets and belong exclusively in server-side storage.

Redirects transfer control to adapters, which save before sending a 303. Application callbacks are synchronous. Production stores enforce expiration and should serialize concurrent mutations to the same session, matching the sequential processing assumed by the callback marker.

PHP dependency APIs such as the entire PSR-7 URI interface are not reimplemented; native language URI types/helpers provide the operations needed by the client. PHP's diagnostic logging and warning mechanisms use the host language's conventions. Browser login against a deployed provider is separate from the automated simulated-provider tests.

Go returns sentinel errors for client failures and `*RedirectError` for redirects. Callers must return these errors to `NewHTTPHandler`. Callbacks return an error instead of throwing. The deprecated `GetUser` is documented with a Go deprecation comment rather than emitting runtime warnings. Nonces use fixed-length `InitVector` values; constructor errors are explicit. Immutable identity data is exposed through `ID()` and `Email()`.

Provider HTTP policy also allows the `.test` hostname suffix (case-insensitive, ignoring trailing DNS dots), for local test providers. The exception does not allow other schemes.

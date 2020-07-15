# Authwave Go client

Connect Go applications to an [Authwave provider](https://github.com/Authwave/provider) with encrypted authentication exchanges and `net/http` integration.

```bash
go get github.com/Authwave/go-client
```

```go
handler, err := authwave.NewHTTPHandler(authwave.HTTPOptions{
    ClientKey: clientKey,
    Store: authwave.NewMemorySessionStore(), // Development only.
    InsecureCookie: true, // Local HTTP only.
}, func(auth *authwave.Authenticator, request *http.Request) (*authwave.Response, error) {
    if request.URL.Path == "/login" {
        auth.SetReturnURI("/")
        if err := auth.Login(nil); err != nil { return nil, err }
    }
    return &authwave.Response{Body: []byte("Welcome")}, nil
})
if err != nil { log.Fatal(err) }
http.ListenAndServe(":3000", handler)
```

Import the package as `authwave "github.com/Authwave/go-client"`. See the complete [server example](examples/server/main.go) and [wiki](https://github.com/Authwave/go-client/wiki) for login, session restoration and logout.

The provider-issued key stays on the server. The final underscore separates the deployment identifier from the raw 32-byte secret. `AuthwaveHost` defaults to `login.authwave.com`.

Go 1.21 or later is required. Production applications need HTTPS and a shared persistent `SessionStore`; cookies are Secure by default. Serialized session records contain sensitive token data. Store them on the server. Return authentication and redirect errors to the adapter so it can save the session before output.

## Development

```bash
go test -race ./...
go vet ./...
```

Tests include 68 deterministic PHP-reference scenarios and complete HTTP flows with simulated provider responses. Set `AUTHWAVE_PHP_REFERENCE` to a PHP checkout with installed Composer dependencies to verify the fixtures against the live PHP source.

[PARITY.md](PARITY.md) maps each PHP source class to the Go API and describes runtime adaptations.

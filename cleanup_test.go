package authwave

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

// A map-only container has no browser session ID.
type cleanupSession struct{ *GlobalSessionContainer }

func (s *cleanupSession) Regenerate() error { return nil }
func TestCallbackCleanupStaysLocal(t *testing.T) {
	cases := [][2]string{
		{"//evil.example/path", "/path"},
		{"//evil.example", "/"},
		{"https://evil.example/path", "/path"},
		{"https://user:pass@evil.example/path", "/path"},
		{"https://app.example//evil.example/path", "/evil.example/path"},
		{"/%2F%2Fevil.example/path", "/%2F%2Fevil.example/path"},
		{"/members/a%2Fb", "/members/a%2Fb"},
		{"/members/orders", "/members/orders"},
	}
	for _, c := range cases {
		t.Run(c[0], func(t *testing.T) {
			session, _ := NewGlobalSessionContainer(map[string]any{})
			_, err := NewAuthenticator(Options{ClientKey: "deployment_" + strings.Repeat("s", 32), CurrentURIPath: c[0] + "?keep=%7e&flag&AUTHWAVE_RESPONSE_DATA=anything#details", Session: session})
			var redirect *RedirectError
			if !errors.As(err, &redirect) {
				t.Fatal(err)
			}
			if redirect.Code != 303 || redirect.URI != c[1]+"?keep=%7e&flag#details" {
				t.Fatal(redirect)
			}
			local, e := url.Parse(redirect.URI)
			if e != nil || local.Scheme != "" || local.Host != "" || !strings.HasPrefix(redirect.URI, "/") || strings.HasPrefix(redirect.URI, "//") {
				t.Fatal("non-local cleanup", redirect.URI, e)
			}
		})
	}
}
func TestBackslashCleanupStaysLocal(t *testing.T) {
	for _, path := range []string{`/\evil.example/path`, `x:/\evil.example/path`} {
		session, _ := NewGlobalSessionContainer(map[string]any{})
		_, err := NewAuthenticator(Options{ClientKey: "deployment_" + strings.Repeat("s", 32), CurrentURIPath: path + "?AUTHWAVE_RESPONSE_DATA=anything", Session: session})
		var redirect *RedirectError
		if !errors.As(err, &redirect) {
			t.Fatal(err)
		}
		if !strings.HasPrefix(redirect.URI, "/") || strings.HasPrefix(redirect.URI, "//") || strings.Contains(redirect.URI, `\`) {
			t.Fatal(redirect.URI)
		}
	}
}
func TestAuthenticatedCleanupPreservesSavedQueryAndEncodedPath(t *testing.T) {
	token := testToken(t)
	query := "filter=original&flag&encoded=%7e"
	session, _ := NewGlobalSessionContainer(map[string]any{SessionStoreKey: NewSessionData(token, nil, &query)})
	cipher, err := Encrypt(`{"id":"user-id","email":"person@example.com"}`, token.SessionIV, token.Secret)
	if err != nil {
		t.Fatal(err)
	}
	_, err = NewAuthenticator(Options{ClientKey: "deployment_" + token.Secret, CurrentURIPath: "https://user:pass@evil.example//members/a%2Fb?AUTHWAVE_RESPONSE_DATA=" + escape(cipher.String()) + "#details", Session: &cleanupSession{session}})
	var redirect *RedirectError
	if !errors.As(err, &redirect) || redirect.URI != "/members/a%2Fb?filter=original&flag&encoded=%7e#details" {
		t.Fatal(err)
	}
	value, err := session.Get(SessionStoreKey)
	if err != nil || value.(*SessionData).Data.GetID() != "user-id" {
		t.Fatal(value, err)
	}
}
func TestCleanupRemovesDuplicateResponseParameters(t *testing.T) {
	session, _ := NewGlobalSessionContainer(map[string]any{})
	_, err := NewAuthenticator(Options{ClientKey: "deployment_" + strings.Repeat("s", 32), CurrentURIPath: "//evil.example/path?AUTHWAVE_RESPONSE_DATA=one&flag&AUTHWAVE_RESPONSE_DATA=two&next=https://evil.example", Session: session})
	var redirect *RedirectError
	if !errors.As(err, &redirect) || redirect.URI != "/path?flag&next=https://evil.example" {
		t.Fatal(err)
	}
}
func TestHTTPCallbackCleanupHeaderStaysLocal(t *testing.T) {
	handler, err := NewHTTPHandler(HTTPOptions{ClientKey: "deployment_" + strings.Repeat("s", 32), Store: NewMemorySessionStore()}, func(*Authenticator, *http.Request) (*Response, error) {
		t.Fatal("cleanup should redirect before the handler")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "//evil.example/path?keep=1&AUTHWAVE_RESPONSE_DATA=anything", nil))
	if response.Code != 303 || response.Header().Get("Location") != "/path?keep=1" {
		t.Fatal(response.Code, response.Header())
	}
}

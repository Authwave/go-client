package authwave

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func providerCallback(t *testing.T, location string) string {
	t.Helper()
	u, err := url.Parse(location)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	ivBytes, _ := base64.StdEncoding.DecodeString(q.Get("i"))
	iv, err := (InitVector{}).WithBytes(ivBytes)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := Decrypt(q.Get("c"), iv, strings.Repeat("s", 32))
	if err != nil {
		t.Fatal(err)
	}
	secretIV, _ := base64.StdEncoding.DecodeString(plain[strings.LastIndex(plain, "&secretIv=")+10:])
	sessionIV, err := (InitVector{}).WithBytes(secretIV)
	if err != nil {
		t.Fatal(err)
	}
	cipher, _ := Encrypt(`{"id":"user-id","email":"person@example.com"}`, sessionIV, strings.Repeat("s", 32))
	return "/callback?AUTHWAVE_RESPONSE_DATA=" + escape(cipher.String())
}
func TestHTTPRoundTrip(t *testing.T) {
	store := NewMemorySessionStore()
	handler, err := NewHTTPHandler(HTTPOptions{ClientKey: "deployment_" + strings.Repeat("s", 32), Store: store, InsecureCookie: true}, func(auth *Authenticator, r *http.Request) (*Response, error) {
		if r.URL.Path == "/login" {
			auth.SetReturnURI("/callback")
			if err := auth.Login(nil); err != nil {
				return nil, err
			}
		}
		if r.URL.Path == "/logout" {
			destination := "/signed-out"
			if err := auth.Logout(&destination, nil); err != nil {
				return nil, err
			}
		}
		var id any
		if auth.IsLoggedIn() {
			user, _ := auth.GetAuthUser()
			id = user.ID()
		}
		body, _ := json.Marshal(map[string]any{"loggedIn": auth.IsLoggedIn(), "id": id})
		return &Response{Body: body}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(path string, cookie *http.Cookie) *httptest.ResponseRecorder {
		request := httptest.NewRequest("GET", path, nil)
		if cookie != nil {
			request.AddCookie(cookie)
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	first := invoke("/login", nil)
	if first.Code != 303 {
		t.Fatal(first.Code, first.Body.String())
	}
	cookie := first.Result().Cookies()[0]
	if cookie.HttpOnly != true || cookie.SameSite != http.SameSiteLaxMode {
		t.Fatal(cookie)
	}
	completed := invoke(providerCallback(t, first.Header().Get("Location")), cookie)
	if completed.Code != 303 {
		t.Fatal(completed.Code, completed.Body.String())
	}
	if completed.Header().Get("Location") != "/callback" {
		t.Fatal(completed.Header())
	}
    oldCookie := cookie
	cookie = completed.Result().Cookies()[0]
    if cookie.Value==oldCookie.Value {t.Fatal("session ID was not rotated")}
    oldSession:=invoke("/callback",oldCookie)
    if oldSession.Body.String()!=`{"id":null,"loggedIn":false}` {t.Fatal("old ID restored identity",oldSession.Body.String())}
    if replay:=invoke(providerCallback(t,first.Header().Get("Location")),oldCookie);replay.Code!=303 {t.Fatal("old response replay was not cleaned",replay.Code)}

	restored := invoke("/callback", cookie)
	if restored.Body.String() != `{"id":"user-id","loggedIn":true}` || restored.Header().Get("Cache-Control") != "no-store" {
		t.Fatal(restored.Body.String(), restored.Header())
	}
	outsider := invoke("/callback", nil)
	if outsider.Body.String() != `{"id":null,"loggedIn":false}` {
		t.Fatal(outsider.Body.String())
	}
	if invoke("/logout", cookie).Code != 303 {
		t.Fatal("logout failed")
	}
	if invoke("/signed-out", cookie).Body.String() != `{"id":null,"loggedIn":false}` {
		t.Fatal("stale identity")
	}
}

type failingStore struct{}

func (failingStore) Delete(context.Context, string) error { return nil }

func (failingStore) Load(context.Context, string) (map[string]any, error) { return nil, nil }
func (failingStore) Save(context.Context, string, map[string]any, time.Time) error {
	return errors.New("save failed")
}
func TestHTTPStoreFailureAndExpiry(t *testing.T) {
	handler, err := NewHTTPHandler(HTTPOptions{ClientKey: "deployment_" + strings.Repeat("s", 32), Store: failingStore{}}, func(a *Authenticator, r *http.Request) (*Response, error) { return nil, a.Login(nil) })
	if err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest("GET", "/login", nil))
	if response.Code != 500 || response.Header().Get("Location") != "" {
		t.Fatal(response.Code, response.Header())
	}
	store := NewMemorySessionStore()
	_ = store.Save(context.Background(), "expired", map[string]any{}, time.Now().Add(-time.Second))
	data, err := store.Load(context.Background(), "expired")
	if err != nil || data != nil {
		t.Fatal(data, err)
	}
	if _, err = NewHTTPHandler(HTTPOptions{}, nil); !errors.Is(err, ErrSessionNotStarted) {
		t.Fatal(err)
	}
}
func TestHTTPCallbackFailurePersistsMarker(t *testing.T) {
	calls := 0
	handler, err := NewHTTPHandler(HTTPOptions{ClientKey: "deployment_" + strings.Repeat("s", 32), Store: NewMemorySessionStore(), OnAuthenticated: func(*AuthUser) error { calls++; return errors.New("app failed") }}, func(a *Authenticator, r *http.Request) (*Response, error) {
		if r.URL.Path == "/login" {
			return nil, a.Login(nil)
		}
		return &Response{Body: []byte("ok")}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	invoke := func(path string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	first := invoke("/login", nil)
	cookie := first.Result().Cookies()[0]
	path := providerCallback(t, first.Header().Get("Location"))
	if invoke(path, cookie).Code != 500 {
		t.Fatal("callback failure hidden")
	}
	if invoke(path, cookie).Code != 303 || calls != 1 {
		t.Fatal("callback repeated", calls)
	}
}

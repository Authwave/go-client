package authwave

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestCoreRotationRequiredBeforeIdentity(t *testing.T) {
	token := testToken(t)
	data := map[string]any{SessionStoreKey: NewSessionData(token, nil, nil)}
	session, _ := NewGlobalSessionContainer(data)
	cipher, _ := Encrypt(`{"id":"user-id","email":"email"}`, token.SessionIV, token.Secret)
	options := Options{ClientKey: "deployment_" + token.Secret, CurrentURIPath: "/?AUTHWAVE_RESPONSE_DATA=" + escape(cipher.String()), Session: session}
	if _, err := NewAuthenticator(options); !errors.Is(err, ErrSessionRegeneration) {
		t.Fatal(err)
	}
	if _, err := data[SessionStoreKey].(*SessionData).GetData(); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatal("identity stored without rotation", err)
	}
	rotated := false
	session, _ = NewGlobalSessionContainer(data, func() error {
		if data[SessionStoreKey].(*SessionData).Data != nil {
			t.Fatal("identity was stored before rotation")
		}
		rotated = true
		return nil
	})
	options.Session = session
	options.OnAuthenticated = func(*AuthUser) error {
		if !rotated {
			t.Fatal("callback ran before rotation")
		}
		return nil
	}
	if _, err := NewAuthenticator(options); err == nil {
		t.Fatal("expected redirect")
	}
	if !rotated {
		t.Fatal("rotation was not requested")
	}
}

func TestCoreRotationFailureStopsAuthentication(t *testing.T) {
	token := testToken(t)
	data := map[string]any{SessionStoreKey: NewSessionData(token, nil, nil)}
	failure := errors.New("rotation failed")
	session, _ := NewGlobalSessionContainer(data, func() error { return failure })
	cipher, _ := Encrypt(`{"id":"user-id","email":"email"}`, token.SessionIV, token.Secret)
	called := false
	_, err := NewAuthenticator(Options{ClientKey: "deployment_" + token.Secret, CurrentURIPath: "/?AUTHWAVE_RESPONSE_DATA=" + escape(cipher.String()), Session: session, OnAuthenticated: func(*AuthUser) error { called = true; return nil }})
	if !errors.Is(err, failure) || called || data[SessionStoreKey].(*SessionData).Data != nil {
		t.Fatal(err, called, data)
	}
}

type invalidationStore struct {
	*MemorySessionStore
	fail bool
}

func (s *invalidationStore) Delete(ctx context.Context, id string) error {
	if s.fail {
		return errors.New("delete failed")
	}
	return s.MemorySessionStore.Delete(ctx, id)
}
func TestHTTPInvalidationFailureDoesNotSaveAuthenticatedState(t *testing.T) {
	token := testToken(t)
	oldID := strings.Repeat("a", 64)
	store := &invalidationStore{MemorySessionStore: NewMemorySessionStore(), fail: true}
	data := map[string]any{SessionStoreKey: NewSessionData(token, nil, nil), "basket": []string{"tea"}}
	if err := store.Save(context.Background(), oldID, data, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	loginURI, err := NewLoginURI(token, "/callback", "deployment", DefaultBaseRemoteURI)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHTTPHandler(HTTPOptions{ClientKey: "deployment_" + token.Secret, Store: store}, func(*Authenticator, *http.Request) (*Response, error) {
		t.Fatal("callback should redirect")
		return nil, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", providerCallback(t, loginURI), nil)
	request.AddCookie(&http.Cookie{Name: "authwave.sid", Value: oldID})
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, request)
	if result.Code != 500 || result.Header().Get("Location") != "" {
		t.Fatal(result.Code, result.Header())
	}
	old, err := store.Load(context.Background(), oldID)
	if err != nil {
		t.Fatal(err)
	}
	session, _ := NewGlobalSessionContainer(old)
	value, err := session.Get(SessionStoreKey)
	if err != nil {
		t.Fatal(err)
	}
	if value.(*SessionData).Data != nil {
		t.Fatal("old session was authenticated")
	}
	store.mu.Lock()
	defer store.mu.Unlock()
	if len(store.entries) != 1 {
		t.Fatal("new identity was saved despite invalidation failure")
	}
}
func TestHTTPFakeLoginRotatesAndPreservesBasket(t *testing.T) {
	store := NewMemorySessionStore()
	oldID := strings.Repeat("a", 64)
	if err := store.Save(context.Background(), oldID, map[string]any{"basket": []string{"tea"}}, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHTTPHandler(HTTPOptions{ClientKey: "deployment_" + strings.Repeat("s", 32), Store: store}, func(a *Authenticator, r *http.Request) (*Response, error) {
		return nil, a.FakeLogin("developer", nil, "/")
	})
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", "/fake", nil)
	request.AddCookie(&http.Cookie{Name: "authwave.sid", Value: oldID})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 303 {
		t.Fatal(response.Code)
	}
	newID := response.Result().Cookies()[0].Value
	if newID == oldID {
		t.Fatal("fake login did not rotate")
	}
	old, err := store.Load(context.Background(), oldID)
	if err != nil || old != nil {
		t.Fatal(old, err)
	}
	current, err := store.Load(context.Background(), newID)
	if err != nil {
		t.Fatal(err)
	}
	if current["basket"].([]any)[0] != "tea" {
		t.Fatal("basket was lost")
	}
	session, _ := NewGlobalSessionContainer(current)
	auth, err := NewAuthenticator(Options{ClientKey: "deployment_" + strings.Repeat("s", 32), CurrentURIPath: "/", Session: session})
	if err != nil || !auth.IsLoggedIn() {
		t.Fatal(err)
	}
}

type aliasingStore struct {
	data map[string]any
	id   string
	t    *testing.T
}

func (s *aliasingStore) Load(ctx context.Context, id string) (map[string]any, error) {
	if id == s.id {
		return s.data, nil
	}
	return nil, nil
}
func (s *aliasingStore) Save(ctx context.Context, id string, data map[string]any, expires time.Time) error {
	return nil
}
func (s *aliasingStore) Delete(ctx context.Context, id string) error {
	session, _ := NewGlobalSessionContainer(s.data)
	value, err := session.Get(SessionStoreKey)
	if err != nil {
		s.t.Fatal(err)
	}
	if value.(*SessionData).Data != nil {
		s.t.Fatal("request mutated authenticated state under the old ID")
	}
	return nil
}
func TestHTTPDoesNotMutateStoreOwnedMapBeforeInvalidation(t *testing.T) {
	token := testToken(t)
	store := &aliasingStore{data: map[string]any{SessionStoreKey: NewSessionData(token, nil, nil)}, id: strings.Repeat("a", 64), t: t}
	loginURI, err := NewLoginURI(token, "/callback", "deployment", DefaultBaseRemoteURI)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHTTPHandler(HTTPOptions{ClientKey: "deployment_" + token.Secret, Store: store}, func(*Authenticator, *http.Request) (*Response, error) { return nil, nil })
	if err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest("GET", providerCallback(t, loginURI), nil)
	request.AddCookie(&http.Cookie{Name: "authwave.sid", Value: store.id})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 303 {
		t.Fatal(response.Code)
	}
}

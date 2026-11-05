package authwave

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func testToken(t *testing.T) *Token {
	t.Helper()
	token, err := NewToken(strings.Repeat("s", 32))
	if err != nil {
		t.Fatal(err)
	}
	return token
}
func TestTokenCipher(t *testing.T) {
	token := testToken(t)
	c, err := token.GenerateRequestCipher("action=login")
	if err != nil {
		t.Fatal(err)
	}
	same, _ := token.GenerateRequestCipher("action=login")
	if c.String() != same.String() {
		t.Fatal("not deterministic")
	}
	other, _ := testToken(t).GenerateRequestCipher("action=login")
	if c.String() == other.String() {
		t.Fatal("nonces reused")
	}
	plain, err := Decrypt(c.String(), token.IV, token.Secret)
	if err != nil || plain != "action=login&secretIv="+token.SessionIV.String() {
		t.Fatal(plain, err)
	}
	for _, idName := range []string{"id", "uuid"} {
		cipher, _ := Encrypt(`{"`+idName+`":"id","email":"email"}`, token.IV, token.Secret)
		user, err := token.Decode(cipher.String())
		if err != nil || user.GetID() != "id" {
			t.Fatal(user, err)
		}
	}
	for _, plain := range []string{"bad", "null", "[]", "{}", `{"id":123,"email":"email"}`, `{"id":"id","email":null}`} {
		cipher, _ := Encrypt(plain, token.IV, token.Secret)
		if _, err := token.Decode(cipher.String()); !errors.Is(err, ErrInvalidUserDataSerialization) {
			t.Fatalf("invalid accepted: %s: %v", plain, err)
		}
	}
	if _, err := token.Decode("bad"); !errors.Is(err, ErrDecryptionFailure) {
		t.Fatal(err)
	}
	if _, err := Encrypt("", token.IV, ""); !errors.Is(err, ErrEncryptionFailure) {
		t.Fatal(err)
	}
	bytes := c.GetBytes()
	bytes[0] ^= 1
	if _, err = Decrypt(CipherText(bytes).String(), token.IV, token.Secret); !errors.Is(err, ErrDecryptionFailure) {
		t.Fatal(err)
	}
}
func TestSessionAndModels(t *testing.T) {
	if _, err := NewGlobalSessionContainer(nil); !errors.Is(err, ErrSessionNotStarted) {
		t.Fatal(err)
	}
	if _, err := NewAuthenticator(Options{}); !errors.Is(err, ErrSessionNotStarted) {
		t.Fatal(err)
	}
	if _, err := (&SessionData{}).GetToken(); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatal(err)
	}
	if _, err := (&SessionData{}).GetData(); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatal(err)
	}
	token := testToken(t)
	message := "Welcome"
	query := "flag&encoded=%7e"
	data := NewSessionData(token, NewUserResponseData("id", "email", &message), &query)
	data.MarkAuthenticationCallbackInvoked()
	session, _ := NewGlobalSessionContainer(map[string]any{}, func() error { return nil })
	_ = session.Set(SessionStoreKey, data)
	encoded, _ := json.Marshal(session.data)
	var raw map[string]any
	_ = json.Unmarshal(encoded, &raw)
	restored, _ := NewGlobalSessionContainer(raw, func() error { return nil })
	value, err := restored.Get(SessionStoreKey)
	if err != nil {
		t.Fatal(err)
	}
	d := value.(*SessionData)
	if !d.HasInvokedAuthenticationCallback() || *d.GetReturnQuery() != query || *d.Data.GetMessage() != message {
		t.Fatal(d)
	}
	c1, _ := d.Token.GenerateRequestCipher("")
	c2, _ := token.GenerateRequestCipher("")
	if c1.String() != c2.String() {
		t.Fatal("token serialization changed")
	}
	_ = restored.Remove(SessionStoreKey)
	if restored.Contains(SessionStoreKey) {
		t.Fatal("remove failed")
	}
	user := NewAuthUser("id", "email")
	if user.ID() != "id" || user.Email() != "email" {
		t.Fatal(user)
	}
}
func TestCallbackAtMostOnceAfterFailure(t *testing.T) {
	token := testToken(t)
	query := "tab=orders"
	state := map[string]any{}
	session, _ := NewGlobalSessionContainer(state, func() error { return nil })
	_ = session.Set(SessionStoreKey, NewSessionData(token, nil, &query))
	cipher, _ := Encrypt(`{"id":"user-id","email":"email"}`, token.SessionIV, token.Secret)
	uri := "/?AUTHWAVE_RESPONSE_DATA=" + escape(cipher.String())
	calls := 0
	options := Options{ClientKey: "deployment_" + token.Secret, CurrentURIPath: uri, Session: session, OnAuthenticated: func(*AuthUser) error { calls++; return errors.New("app failed") }}
	if _, err := NewAuthenticator(options); err == nil || err.Error() != "app failed" {
		t.Fatal(err)
	}
	options.RedirectHandler = func(uri string, code int) error {
		if uri != "/?tab=orders" {
			t.Fatal(uri)
		}
		return nil
	}
	auth, err := NewAuthenticator(options)
	if err != nil || calls != 1 || !auth.IsLoggedIn() {
		t.Fatal(calls, err)
	}
	u, _ := auth.GetAuthUser()
	old, _ := auth.GetUser()
	if u != old {
		t.Fatal("legacy user changed identity")
	}
}
func TestFakeLoginAndDefaultRedirect(t *testing.T) {
	session, _ := NewGlobalSessionContainer(map[string]any{}, func() error { return nil })
	auth, err := NewAuthenticator(Options{ClientKey: "deployment_" + strings.Repeat("s", 32), CurrentURIPath: "/", Session: session})
	if err != nil {
		t.Fatal(err)
	}
	err = auth.FakeLogin("dev", nil, "/")
	var redirect *RedirectError
	if !errors.As(err, &redirect) || redirect.Code != 303 {
		t.Fatal(err)
	}
	if auth.IsLoggedIn() {
		t.Fatal("fake login changed current user")
	}
	next, err := NewAuthenticator(Options{ClientKey: auth.options.ClientKey, CurrentURIPath: redirect.URI, Session: session, RedirectHandler: func(string, int) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	user, _ := next.GetAuthUser()
	if user.Email() != FakeEmail {
		t.Fatal(user)
	}
	if err = next.Logout(nil, nil); err != nil || next.IsLoggedIn() || session.Contains(SessionStoreKey) {
		t.Fatal(err)
	}
	if _, err = next.GetAuthUser(); !errors.Is(err, ErrNotLoggedIn) {
		t.Fatal(err)
	}
	admin, err := next.GetAdminURI()
	if err != nil || admin != "https://login.authwave.com/admin/" {
		t.Fatal(admin, err)
	}
	if err = auth.Login(nil); !errors.As(err, &redirect) {
		t.Fatal(err)
	}
	if err = auth.Logout(nil, nil); !errors.As(err, &redirect) {
		t.Fatal(err)
	}
}

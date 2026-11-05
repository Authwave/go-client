package authwave

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type parityFixture struct {
	Case     map[string]json.RawMessage `json:"case"`
	Expected json.RawMessage            `json:"expected"`
}

func loadFixtures(t *testing.T) []parityFixture {
	t.Helper()
	data, err := os.ReadFile("testdata/parity.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures []parityFixture
	if err = json.Unmarshal(data, &fixtures); err != nil {
		t.Fatal(err)
	}
	return fixtures
}
func stringValue(c map[string]json.RawMessage, key, fallback string) string {
	raw := c[key]
	if len(raw) == 0 || string(raw) == "null" {
		return fallback
	}
	var result string
	_ = json.Unmarshal(raw, &result)
	return result
}
func nullableString(c map[string]json.RawMessage, key string) *string {
	raw := c[key]
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	v := stringValue(c, key, "")
	return &v
}
func boolValue(c map[string]json.RawMessage, key string) bool { return string(c[key]) == "true" }
func TestPHPParity(t *testing.T) {
	for i, fixture := range loadFixtures(t) {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			c := fixture.Case
			secret := strings.Repeat("s", 32)
			var sessionIV, iv InitVector
			copy(sessionIV[:], strings.Repeat("a", 24))
			copy(iv[:], strings.Repeat("f", 24))
			token := NewTokenWithIVs(secret, sessionIV, iv)
			state := map[string]any{"basket": []string{"tea"}}
			session, _ := NewGlobalSessionContainer(state, func() error { return nil })
			switch stringValue(c, "state", "") {
			case "pending":
				_ = session.Set(SessionStoreKey, NewSessionData(token, nil, nullableString(c, "returnQuery")))
			case "user":
				_ = session.Set(SessionStoreKey, NewSessionData(token, NewUserResponseData("user-id", stringValue(c, "email", "person@example.com"), nil), nil))
			}
			uri := stringValue(c, "uri", "/account?tab=security")
			if response, ok := c["response"]; ok {
				cipher, err := Encrypt(string(response), sessionIV, secret)
				if err != nil {
					t.Fatal(err)
				}
				value := cipher.String()
				if !boolValue(c, "rawPlus") {
					value = escape(value)
				}
				sep := "?"
				if strings.Contains(uri, "?") {
					sep = "&"
				}
				uri += sep + ResponseQueryParameter + "=" + value
			}
			redirects := make([][]any, 0)
			calls := 0
			options := Options{ClientKey: "deployment_with_underscores_" + secret, CurrentURIPath: uri, AuthwaveHost: stringValue(c, "host", DefaultBaseRemoteURI), Session: session, RedirectHandler: func(uri string, code int) error { redirects = append(redirects, []any{uri, code}); return nil }}
			if boolValue(c, "callback") {
				options.OnAuthenticated = func(user *AuthUser) error {
					calls++
					if boolValue(c, "throwCallback") {
						return errors.New("callback")
					}
					return nil
				}
			}
			auth, err := NewAuthenticator(options)
			if err == nil {
				if returnURI := nullableString(c, "returnUri"); returnURI != nil {
					auth.SetReturnURI(*returnURI)
				}
				switch stringValue(c, "action", "") {
				case "login":
					err = auth.Login(token)
				case "logout":
					err = auth.Logout(nullableString(c, "redirectTo"), token)
				}
			}
			var errorName any
			if err != nil {
				switch {
				case errors.Is(err, ErrInsecureProtocol):
					errorName = "InsecureProtocolException"
				case errors.Is(err, ErrInvalidUserDataSerialization):
					errorName = "TypeError"
				case err.Error() == "callback":
					errorName = "RuntimeException"
				default:
					errorName = err.Error()
				}
			}
			storedValue, e := session.Get(SessionStoreKey)
			if e != nil {
				t.Fatal(e)
			}
			stored, _ := storedValue.(*SessionData)
			var data, user, returnQuery, invoked any
			if stored != nil {
				if stored.Data != nil {
					data = []string{stored.Data.UserID, stored.Data.UserEmail}
				}
				if stored.ReturnQuery != nil {
					returnQuery = *stored.ReturnQuery
				}
				invoked = stored.CallbackInvoked
			}
			if auth != nil && auth.IsLoggedIn() {
				u, _ := auth.GetAuthUser()
				user = []string{u.ID(), u.Email()}
			}
			actual := map[string]any{"redirects": redirects, "calls": calls, "error": errorName, "user": user, "stored": stored != nil, "data": data, "returnQuery": returnQuery, "invoked": invoked, "basket": state["basket"]}
			encoded, _ := json.Marshal(actual)
			var got, want any
			_ = json.Unmarshal(encoded, &got)
			_ = json.Unmarshal(fixture.Expected, &want)
			g, _ := json.Marshal(got)
			w, _ := json.Marshal(want)
			if !bytes.Equal(g, w) {
				t.Fatalf("case %s\ngot  %s\nwant %s", mustJSON(c), g, w)
			}
		})
	}
}
func mustJSON(v any) string { b, _ := json.Marshal(v); return string(b) }
func TestLivePHPReference(t *testing.T) {
	reference := os.Getenv("AUTHWAVE_PHP_REFERENCE")
	if reference == "" {
		return
	}
	fixtures := loadFixtures(t)
	cases := make([]map[string]json.RawMessage, len(fixtures))
	expected := make([]json.RawMessage, len(fixtures))
	for i, f := range fixtures {
		cases[i] = f.Case
		expected[i] = f.Expected
	}
	input, _ := json.Marshal(cases)
	cmd := exec.Command("php", filepath.Join("testdata", "php-oracle.php"), reference)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.Output()
	if err != nil {
		t.Fatalf("PHP oracle: %v: %s", err, output)
	}
	var got, want any
	if err = json.Unmarshal(output, &got); err != nil {
		t.Fatal(err)
	}
	expectedJSON, _ := json.Marshal(expected)
	_ = json.Unmarshal(expectedJSON, &want)
	if mustJSON(got) != mustJSON(want) {
		t.Fatal("live PHP differs from stored parity fixtures")
	}
}

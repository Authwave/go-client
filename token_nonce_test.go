package authwave

import (
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"testing"
)

func TestTokenRejectsChangedRequests(t *testing.T) {
	for _, messages := range [][2]string{{"action=login", "action=logout"}, {"", "action=login"}, {"action=login", ""}, {"action=login&returnQuery=page%3D1", "action=login&returnQuery=page%3D2"}} {
		token := testToken(t)
		iv := token.IV
		first, err := token.GenerateRequestCipher(messages[0])
		if err != nil {
			t.Fatal(err)
		}
		if _, err = token.GenerateRequestCipher(messages[1]); !errors.Is(err, ErrTokenReuse) {
			t.Fatal(err)
		}
		again, err := token.GenerateRequestCipher(messages[0])
		if err != nil || again.String() != first.String() || token.IV != iv {
			t.Fatal(err)
		}
		plain, err := Decrypt(first.String(), iv, token.Secret)
		if err != nil || plain != messages[0]+"&secretIv="+token.SessionIV.String() {
			t.Fatal(plain, err)
		}
	}
}
func TestTokenBindingSurvivesSessionJSON(t *testing.T) {
	token := testToken(t)
	first, err := token.GenerateRequestCipher("action=login")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(NewSessionData(token, nil, nil))
	if err != nil {
		t.Fatal(err)
	}
	var session SessionData
	if err = json.Unmarshal(data, &session); err != nil {
		t.Fatal(err)
	}
	again, err := session.Token.GenerateRequestCipher("action=login")
	if err != nil || again.String() != first.String() {
		t.Fatal(err)
	}
	if _, err = session.Token.GenerateRequestCipher("action=logout"); !errors.Is(err, ErrTokenReuse) {
		t.Fatal(err)
	}
}
func TestUnusedTokenJSONCanEncryptFirstRequest(t *testing.T) {
	encoded, err := json.Marshal(testToken(t))
	if err != nil {
		t.Fatal(err)
	}
	var restored Token
	if err = json.Unmarshal(encoded, &restored); err != nil {
		t.Fatal(err)
	}
	if _, err = restored.GenerateRequestCipher("action=login"); err != nil {
		t.Fatal(err)
	}
}
func TestLegacyTokenCanDecryptButCannotReuseUnknownNonce(t *testing.T) {
	token := testToken(t)
	encoded, err := json.Marshal(map[string]any{"secret": token.Secret, "iv": token.IV, "session_iv": token.SessionIV})
	if err != nil {
		t.Fatal(err)
	}
	var legacy Token
	if err = json.Unmarshal(encoded, &legacy); err != nil {
		t.Fatal(err)
	}
	cipher, err := Encrypt(`{"id":"user-id","email":"person@example.com"}`, token.IV, token.Secret)
	if err != nil {
		t.Fatal(err)
	}
	data, err := legacy.Decode(cipher.String())
	if err != nil || data.GetID() != "user-id" {
		t.Fatal(data, err)
	}
	if _, err = legacy.GenerateRequestCipher("action=login"); !errors.Is(err, ErrTokenReuse) {
		t.Fatal(err)
	}
}
func TestFailedEncryptionDoesNotBindToken(t *testing.T) {
	token, err := NewToken("")
	if err != nil {
		t.Fatal(err)
	}
	for _, message := range []string{"action=login", "action=logout"} {
		if _, err = token.GenerateRequestCipher(message); !errors.Is(err, ErrEncryptionFailure) {
			t.Fatal(err)
		}
	}
}
func TestCompletePlaintextIncludesSessionIV(t *testing.T) {
	token := testToken(t)
	if _, err := token.GenerateRequestCipher("action=login"); err != nil {
		t.Fatal(err)
	}
	token.SessionIV[0] ^= 1
	if _, err := token.GenerateRequestCipher("action=login"); !errors.Is(err, ErrTokenReuse) {
		t.Fatal(err)
	}
}
func TestURIBuildersRequireSeparateTokens(t *testing.T) {
	token := testToken(t)
	first, err := NewLoginURI(token, "/callback", "deployment", DefaultBaseRemoteURI)
	if err != nil {
		t.Fatal(err)
	}
	again, err := NewLoginURI(token, "/callback", "deployment", DefaultBaseRemoteURI)
	if err != nil || again != first {
		t.Fatal(err)
	}
	if _, err = NewLogoutURI(token, "/callback", "deployment", DefaultBaseRemoteURI, nil); !errors.Is(err, ErrTokenReuse) {
		t.Fatal(err)
	}
	if _, err = NewLogoutURI(testToken(t), "/callback", "deployment", DefaultBaseRemoteURI, nil); err != nil {
		t.Fatal(err)
	}
}
func TestRejectedLoginPreservesPendingExchange(t *testing.T) {
	token := testToken(t)
	pending := NewSessionData(testToken(t), nil, nil)
	state := map[string]any{SessionStoreKey: pending, "basket": []string{"tea"}}
	session, _ := NewGlobalSessionContainer(state)
	auth, err := NewAuthenticator(Options{ClientKey: "deployment_" + strings.Repeat("s", 32), CurrentURIPath: "/callback", Session: session})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = token.GenerateRequestCipher("action=logout"); err != nil {
		t.Fatal(err)
	}
	if err = auth.Login(token); !errors.Is(err, ErrTokenReuse) {
		t.Fatal(err)
	}
	if state[SessionStoreKey] != pending || state["basket"].([]string)[0] != "tea" {
		t.Fatal("pending exchange changed")
	}
}
func TestConcurrentDifferentRequestsCannotBothEncrypt(t *testing.T) {
	token := testToken(t)
	start := make(chan struct{})
	results := make(chan error, 2)
	var workers sync.WaitGroup
	for _, message := range []string{"action=login", "action=logout"} {
		workers.Add(1)
		go func(message string) {
			defer workers.Done()
			<-start
			_, err := token.GenerateRequestCipher(message)
			results <- err
		}(message)
	}
	close(start)
	workers.Wait()
	close(results)
	success, rejected := 0, 0
	for err := range results {
		if err == nil {
			success++
		} else if errors.Is(err, ErrTokenReuse) {
			rejected++
		} else {
			t.Fatal(err)
		}
	}
	if success != 1 || rejected != 1 {
		t.Fatal(success, rejected)
	}
}

package authwave

import (
	"encoding/json"
	"sync"
)

// Token must not be copied; create a new token for each different request.
type Token struct {
	mu               sync.Mutex
	requestPlaintext *string
	Secret           string     `json:"secret"`
	SessionIV        InitVector `json:"session_iv"`
	IV               InitVector `json:"iv"`
}

// NewToken generates both nonces. Use NewTokenWithIVs for deterministic exchange tests.
func NewToken(secret string) (*Token, error) {
	sessionIV, err := NewInitVector()
	if err != nil {
		return nil, err
	}
	iv, err := NewInitVector()
	if err != nil {
		return nil, err
	}
	return NewTokenWithIVs(secret, sessionIV, iv), nil
}
func NewTokenWithIVs(secret string, sessionIV, iv InitVector) *Token {
	return &Token{Secret: secret, SessionIV: sessionIV, IV: iv}
}
func (t *Token) GetIV() InitVector       { return t.IV }
func (t *Token) GetSecretIV() InitVector { return t.SessionIV }
func (t *Token) GenerateRequestCipher(message string) (CipherText, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	plaintext := message + "&secretIv=" + t.SessionIV.String()
	if t.requestPlaintext != nil && *t.requestPlaintext != plaintext {
		return nil, ErrTokenReuse
	}
	cipher, err := Encrypt(plaintext, t.IV, t.Secret)
	if err != nil {
		return nil, err
	}
	t.requestPlaintext = &plaintext
	return cipher, nil
}
func (t *Token) Decode(cipher string) (*UserResponseData, error) {
	plain, err := Decrypt(cipher, t.IV, t.Secret)
	if err != nil {
		return nil, err
	}
	var data map[string]json.RawMessage
	if json.Unmarshal([]byte(plain), &data) != nil || data == nil {
		return nil, ErrInvalidUserDataSerialization
	}
	idValue := data["uuid"]
	if len(idValue) == 0 || string(idValue) == "null" {
		idValue = data["id"]
	}
	var id, email string
	if len(idValue) == 0 || string(idValue) == "null" || json.Unmarshal(idValue, &id) != nil || len(data["email"]) == 0 || string(data["email"]) == "null" || json.Unmarshal(data["email"], &email) != nil {
		return nil, ErrInvalidUserDataSerialization
	}
	return NewUserResponseData(id, email, nil), nil
}

// tokenRecord retains the request binding in server-side session serialisation.
type tokenRecord struct {
	Secret           string     `json:"secret"`
	SessionIV        InitVector `json:"session_iv"`
	IV               InitVector `json:"iv"`
	RequestPlaintext *string    `json:"request_plaintext"`
}

func (t *Token) MarshalJSON() ([]byte, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return json.Marshal(tokenRecord{t.Secret, t.SessionIV, t.IV, t.requestPlaintext})
}
func (t *Token) UnmarshalJSON(data []byte) error {
	var record tokenRecord
	if err := json.Unmarshal(data, &record); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	if _, ok := fields["request_plaintext"]; !ok {
		// A legacy token may already have used its nonce for an unknown plaintext.
		unknown := ""
		record.RequestPlaintext = &unknown
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.Secret, t.SessionIV, t.IV = record.Secret, record.SessionIV, record.IV
	t.requestPlaintext = record.RequestPlaintext
	return nil
}
